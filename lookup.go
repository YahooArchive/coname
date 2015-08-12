package coname

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/yahoo/coname/common"
	"github.com/yahoo/coname/common/vrf"
	"github.com/yahoo/coname/proto"
)

func GetRealmByDomain(cfg *proto.Config, domain string) (ret *proto.RealmConfig, err error) {
	for _, realm := range cfg.Realms {
		for _, pattern := range realm.Domains {
			if pattern == domain { // TODO: implement wildcards?
				if ret != nil && ret != realm {
					return nil, fmt.Errorf("GetRealmByDomain: multiple realms match %q: %v and %v", domain, realm, ret)
				}
				ret = realm
			}
		}
	}
	return nil, fmt.Errorf("GetRealm: unknown domain %q", domain)
}

func GetRealmByUser(cfg *proto.Config, user string) (*proto.RealmConfig, error) {
	indexOfAt := strings.LastIndex(user, "@")
	if indexOfAt == -1 {
		return nil, fmt.Errorf("GetRealm: user must be of the form .*@.* (got %q)", user)
	}
	domain := user[indexOfAt+1:]
	return GetRealmByDomain(cfg, domain)
}

func VerifyLookup(cfg *proto.Config, user string, pf *proto.LookupProof, now time.Time) (keys map[string][]byte, err error) {
	if pf.UserId != "" && pf.UserId != user {
		return nil, fmt.Errorf("VerifyLookup: proof specifies different user ID: %q != %q", pf.UserId, user)
	}
	realm, err := GetRealmByUser(cfg, user)
	if err != nil {
		return nil, err
	}
	if !vrf.Verify(realm.VRFPublic, []byte(user), pf.Entry.Index, pf.IndexProof) {
		return nil, fmt.Errorf("VerifyLookup: VRF verification failed")
	}
	root, err := VerifyConsensus(realm, pf.Ratifications, now)
	if err != nil {
		return
	}

	entryHash := sha256.Sum256(pf.Entry.PreservedEncoding)
	verifiedEntryHash, err := VerifiedLookup(realm.TreeNonce, root, pf.Entry.Index, pf.TreeProof)
	if err != nil {
		return nil, fmt.Errorf("VerifyLookup: failed to verify the lookup: %v", err)
	}
	if !bytes.Equal(entryHash[:], verifiedEntryHash) {
		return nil, fmt.Errorf("VerifyLookup: entry hash %x did not match verified lookup result %x", entryHash, verifiedEntryHash)
	}

	profileHash := sha256.Sum256(pf.Profile.PreservedEncoding)
	if !bytes.Equal(profileHash[:], pf.Entry.ProfileHash) {
		return nil, fmt.Errorf("VerifyLookup: profile does not match the hash in the entry")
	}

	return pf.Profile.Keys, nil
}

func VerifyConsensus(rcg *proto.RealmConfig, ratifications []*proto.SignedEpochHead, now time.Time) (root []byte, err error) {
	if len(ratifications) == 0 {
		return nil, fmt.Errorf("VerifyConsensus: no signed epoch heads provided")
	}
	// check that the first SEH is referenced by all following SEH-s.
	for i := 1; i < len(ratifications); i++ {
		this := ratifications[i]
		prev := ratifications[i-1]
		computedHash := sha256.Sum256(prev.Head.Head.PreservedEncoding)
		if !bytes.Equal(computedHash[:], this.Head.Head.PreviousSummaryHash) {
			return nil, fmt.Errorf("VerifyConsensus: hash chain does not match: %d.prev != h(%d)", i, i-1)
		}
		if prev.Head.Head.Epoch+1 != this.Head.Head.Epoch {
			return nil, fmt.Errorf("VerifyConsensus: epoch chain does not match: %d.epoch != %d.epoch+1", i, i-1)
		}
	}
	// check that the seh is not expired
	if ratifications[0].Head.Head.NextEpochTime.Time().After(now) {
		return nil, fmt.Errorf("VerifyConsensus: epoch expired at %v < %v", ratifications[0].Head.Head.NextEpochTime.Time(), now)
	}
	// check that there are sufficiently many fresh signatures.
	pks := rcg.VerificationPolicy.PublicKeys
	want := rcg.VerificationPolicy.Quorum
	can := common.ListQuorum(want, nil)
	have := make(map[uint64]struct{})
next_verifier:
	for id := range can {
		if common.CheckQuorum(want, have) {
			break // already sufficiently verified, short-circuit
		}
		for _, seh := range ratifications {
			if sig, ok := seh.Signatures[id]; ok &&
				common.VerifySignature(pks[id], seh.Head.PreservedEncoding, sig) {
				have[id] = struct{}{}
				continue next_verifier
			}
		}
	}
	if !common.CheckQuorum(want, have) {
		return nil, fmt.Errorf("VerifyConsensus: insufficient signatures (have %v, want %v)", have, want)
	}

	return ratifications[0].Head.Head.RootHash, nil
}

func VerifiedLookup(treeNonce []byte, rootHash []byte, index []byte, proof *proto.TreeProof) ([]byte, error) {
	// First, reconstruct the partial tree
	reconstructed, err := ReconstructTree(proof, common.ToBits(common.IndexBits, index))
	if err != nil {
		return nil, err
	}
	// Reconstruct the root hash
	reconstructedHash, err := RecomputeHash(treeNonce, reconstructed)
	if err != nil {
		return nil, err
	}
	// Compare root hashes
	if !bytes.Equal(reconstructedHash, rootHash) {
		return nil, fmt.Errorf("Root hashes do not match! Reconstructed %x; wanted %x", reconstructedHash, rootHash)
	}
	// Then, do the lookup
	value, err := common.Lookup(reconstructed, index)
	if err != nil {
		return nil, err
	}
	return value, nil
}

func RecomputeHash(treeNonce []byte, node common.MerkleNode) ([]byte, error) {
	return recomputeHash(treeNonce, []bool{}, node)
}

// assumes ownership of the array underlying prefixBits
func recomputeHash(treeNonce []byte, prefixBits []bool, node common.MerkleNode) ([]byte, error) {
	if node.IsEmpty() {
		return common.HashEmptyBranch(treeNonce, prefixBits), nil
	} else if node.IsLeaf() {
		return common.HashLeaf(treeNonce, node.Index(), node.Depth(), node.Value()), nil
	} else {
		var childHashes [2][common.HashBytes]byte
		for i := 0; i < 2; i++ {
			rightChild := i == 1
			h := node.ChildHash(rightChild)
			if h == nil {
				ch, err := node.Child(rightChild)
				if err != nil {
					return nil, err
				}
				h, err = recomputeHash(treeNonce, append(prefixBits, rightChild), ch)
				if err != nil {
					return nil, err
				}
			}
			copy(childHashes[i][:], h)
		}
		return common.HashInternalNode(prefixBits, &childHashes), nil
	}
}

type ReconstructedNode struct {
	isLeaf bool
	depth  int

	children [2]struct {
		// Only one of the following two may be set
		Omitted []byte
		Present *ReconstructedNode
	}

	index []byte
	value []byte
}

func ReconstructTree(trace *proto.TreeProof, lookupIndexBits []bool) (*ReconstructedNode, error) {
	return reconstructBranch(trace, lookupIndexBits, 0), nil
}

func reconstructBranch(trace *proto.TreeProof, lookupIndexBits []bool, depth int) *ReconstructedNode {
	if depth == len(trace.Neighbors) {
		if trace.ExistingEntryHash == nil {
			return nil
		} else {
			return &ReconstructedNode{
				isLeaf: true,
				depth:  depth,
				index:  trace.ExistingIndex,
				value:  trace.ExistingEntryHash,
			}
		}
	} else {
		node := &ReconstructedNode{
			isLeaf: false,
			depth:  depth,
		}
		presentChild := lookupIndexBits[depth]
		node.children[common.BitToIndex(presentChild)].Present = reconstructBranch(trace, lookupIndexBits, depth+1)
		node.children[common.BitToIndex(!presentChild)].Omitted = trace.Neighbors[depth]
		return node
	}
}

var _ common.MerkleNode = (*ReconstructedNode)(nil)

func (n *ReconstructedNode) IsEmpty() bool {
	return n == nil
}

func (n *ReconstructedNode) IsLeaf() bool {
	return n.isLeaf
}

func (n *ReconstructedNode) Depth() int {
	return n.depth
}

func (n *ReconstructedNode) ChildHash(rightChild bool) []byte {
	return n.children[common.BitToIndex(rightChild)].Omitted
}

func (n *ReconstructedNode) Child(rightChild bool) (common.MerkleNode, error) {
	// Give an error if the lookup algorithm tries to access anything the server didn't provide us.
	if n.children[common.BitToIndex(rightChild)].Omitted != nil {
		return nil, fmt.Errorf("can't access omitted node")
	}
	// This might still be nil if the branch is in fact empty.
	return n.children[common.BitToIndex(rightChild)].Present, nil
}

func (n *ReconstructedNode) Index() []byte {
	return n.index
}

func (n *ReconstructedNode) Value() []byte {
	return n.value
}

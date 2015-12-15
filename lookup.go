package coname

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/vrf"
)

func CheckCommitment(commitment []byte, profile *proto.EncodedProfile) bool {
	// The hash used here is modeled as a random oracle. This means that SHA3
	// is fine but SHA2 is not (consider HMAC-SHA2 instead).
	var commitmentCheck [64]byte
	sha3.ShakeSum256(commitmentCheck[:], profile.Encoding) // the profile includes a nonce
	return bytes.Equal(commitment[:], commitmentCheck[:])
}

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
	if ret == nil {
		err = fmt.Errorf("GetRealm: unknown domain %q", domain)
	}
	return
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
	if !vrf.Verify(realm.VRFPublic, []byte(user), pf.Index, pf.IndexProof) {
		return nil, fmt.Errorf("VerifyLookup: VRF verification failed")
	}
	root, err := VerifyConsensus(realm, pf.Ratifications, now)
	if err != nil {
		return
	}

	verifiedEntryHash, err := reconstructTreeAndLookup(realm.TreeNonce, root, pf.Index, pf.TreeProof)
	if err != nil {
		return nil, fmt.Errorf("VerifyLookup: failed to verify the lookup: %v", err)
	}
	if verifiedEntryHash == nil {
		if pf.Entry != nil {
			return nil, fmt.Errorf("VerifyLookup: non-empty entry %x did not match verified lookup result <nil>", pf.Entry)
		}
		if pf.Profile != nil {
			return nil, fmt.Errorf("VerifyLookup: non-empty profile %x did not match verified lookup result <nil>", pf.Profile)
		}
		return nil, nil
	} else {
		var entryHash [32]byte
		sha3.ShakeSum256(entryHash[:], pf.Entry.Encoding)
		if !bytes.Equal(entryHash[:], verifiedEntryHash) {
			return nil, fmt.Errorf("VerifyLookup: entry hash %x did not match verified lookup result %x", entryHash, verifiedEntryHash)
		}

		if !CheckCommitment(pf.Entry.ProfileCommitment, pf.Profile) {
			return nil, fmt.Errorf("VerifyLookup: profile does not match the hash in the entry")
		}

		return pf.Profile.Keys, nil
	}
}

func VerifyConsensus(rcg *proto.RealmConfig, ratifications []*proto.SignedEpochHead, now time.Time) (root []byte, err error) {
	if len(ratifications) == 0 {
		return nil, fmt.Errorf("VerifyConsensus: no signed epoch heads provided")
	}
	// check that all the SEHs have the same head
	for i := 1; i < len(ratifications); i++ {
		if want, got := ratifications[0].Head.Head.Encoding, ratifications[i].Head.Head.Encoding; !bytes.Equal(want, got) {
			return nil, fmt.Errorf("VerifyConsensus: epoch heads don't match: %x vs %x", want, got)
		}
	}
	// check that the seh corresponds to the realm in question
	if got := ratifications[0].Head.Head.Realm; got != rcg.RealmName {
		return nil, fmt.Errorf("VerifyConsensus: SEH does not match realm: %q != %q", got, rcg.RealmName)
	}
	// check that the seh is not expired
	if t := ratifications[0].Head.Head.IssueTime.Time().Add(rcg.EpochTimeToLive.Duration()); now.After(t) {
		return nil, fmt.Errorf("VerifyConsensus: epoch expired at %v < %v", t, now)
	}
	// check that there are sufficiently many fresh signatures.
	pks := rcg.VerificationPolicy.PublicKeys
	policyQuorum, ok := rcg.VerificationPolicy.PolicyType.(*proto.AuthorizationPolicy_Quorum)
	if !ok {
		return nil, fmt.Errorf("VerifyConsensus: unknown verification policy in realm config: %v", rcg)
	}
	want := policyQuorum.Quorum
	can := ListQuorum(want, nil)
	have := make(map[uint64]struct{})
next_verifier:
	for id := range can {
		if CheckQuorum(want, have) {
			break // already sufficiently verified, short-circuit
		}
		for _, seh := range ratifications {
			if sig, ok := seh.Signatures[id]; ok &&
				VerifySignature(pks[id], seh.Head.Encoding, sig) {
				have[id] = struct{}{}
				continue next_verifier
			}
		}
	}
	if !CheckQuorum(want, have) {
		return nil, fmt.Errorf("VerifyConsensus: insufficient signatures (have %v, want %v)", have, want)
	}

	return ratifications[0].Head.Head.RootHash, nil
}

func reconstructTreeAndLookup(treeNonce []byte, rootHash []byte, index []byte, proof *proto.TreeProof) ([]byte, error) {
	// First, reconstruct the partial tree
	reconstructed, err := ReconstructTree(proof, ToBits(IndexBits, index))
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
	value, err := TreeLookup(reconstructed, index)
	if err != nil {
		return nil, err
	}
	return value, nil
}

func RecomputeHash(treeNonce []byte, node MerkleNode) ([]byte, error) {
	return recomputeHash(treeNonce, []bool{}, node)
}

// assumes ownership of the array underlying prefixBits
func recomputeHash(treeNonce []byte, prefixBits []bool, node MerkleNode) ([]byte, error) {
	if node.IsEmpty() {
		return HashEmptyBranch(treeNonce, prefixBits), nil
	} else if node.IsLeaf() {
		return HashLeaf(treeNonce, node.Index(), node.Depth(), node.Value()), nil
	} else {
		var childHashes [2][HashBytes]byte
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
		return HashInternalNode(prefixBits, &childHashes), nil
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
		node.children[BitToIndex(presentChild)].Present = reconstructBranch(trace, lookupIndexBits, depth+1)
		node.children[BitToIndex(!presentChild)].Omitted = trace.Neighbors[depth]
		return node
	}
}

var _ MerkleNode = (*ReconstructedNode)(nil)

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
	return n.children[BitToIndex(rightChild)].Omitted
}

func (n *ReconstructedNode) Child(rightChild bool) (MerkleNode, error) {
	// Give an error if the lookup algorithm tries to access anything the server didn't provide us.
	if n.children[BitToIndex(rightChild)].Omitted != nil {
		return nil, fmt.Errorf("can't access omitted node")
	}
	// This might still be nil if the branch is in fact empty.
	return n.children[BitToIndex(rightChild)].Present, nil
}

func (n *ReconstructedNode) Index() []byte {
	return n.index
}

func (n *ReconstructedNode) Value() []byte {
	return n.value
}

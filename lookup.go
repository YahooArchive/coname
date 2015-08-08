package coname

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/yahoo/coname/client"
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
	verifiedEntryHash, err := client.VerifiedLookup(realm.TreeNonce, root, pf.Entry.Index, pf.TreeProof)
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

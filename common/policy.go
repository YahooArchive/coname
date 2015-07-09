package common

import (
	"fmt"

	"github.com/yahoo/coname/proto"
)

// VerifyUpdate returns nil iff replacing entry current (nil if none) with next
// is justified given the evidence in update. Globally deterministic.
func VerifyUpdate(current *proto.Entry, update *proto.SignedEntryUpdate) error {
	next := &update.Update.NewEntry
	if current != nil {
		if current.UpdateKey == nil {
			return fmt.Errorf("VerifyUpdate: current.UpdateKey is nil")
		}
		if !VerifySignature(current.UpdateKey, update.Update.PreservedEncoding, update.OldSig) {
			return fmt.Errorf("VerifyUpdate: replacing an entry requires authorization from the old key, but signature verification failed")
		}
		if next.Version < current.Version {
			return fmt.Errorf("VerifyUpdate: entry version must not decrease (got %d < %d)", next.Version, current.Version)
		}
	} else if next.Version != 0 {
		return fmt.Errorf("VerifyUpdate: registering a new entry must use version number 0 (got %d)", next.Version)
	}
	if next.UpdateKey == nil {
		return fmt.Errorf("VerifyUpdate: next.UpdateKey is nil")
	}
	if !VerifySignature(next.UpdateKey, update.Update.PreservedEncoding, update.NewSig) {
		return fmt.Errorf("VerifyUpdate: update needs to be accepted by the new key, but signature verification failed")
	}
	return nil
}

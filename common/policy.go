package common

import (
	"fmt"

	"github.com/yahoo/coname/proto"
)

// VerifyUpdate returns nil iff replacing entry current (nil if none) with next
// is justified given the evidence in update. Globally deterministic.
func VerifyUpdate(current *proto.Entry, update *proto.SignedEntryUpdate, next *proto.Entry) error {
	if current != nil {
		if current.UpdateKey == nil {
			return fmt.Errorf("VerifyUpdate: current.UpdateKey is nil")
		}
		if !VerifySignature(current.UpdateKey, update.Update.PreservedEncoding, update.OldSig) {
			return fmt.Errorf("VerifyUpdate: replacing an entry requires authorization from the old key, but signature verification failed", next.Version, current.Version)
		}
		if next.Version < current.Version {
			return fmt.Errorf("VerifyUpdate: entry version must not decrease (got %d < %d)", next.Version, current.Version)
		}
	}
	if next.UpdateKey == nil {
		return fmt.Errorf("VerifyUpdate: next.UpdateKey is nil")
	}
	if !VerifySignature(next.UpdateKey, update.Update.PreservedEncoding, update.NewSig) {
		return fmt.Errorf("VerifyUpdate: update needs to be accepted by the new key, but signature verification failed", next.Version, current.Version)
	}
	return nil
}

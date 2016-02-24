// Copyright 2014-2015 The Dename Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

package keyserver

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"math"
	"strings"

	"github.com/yahoo/coname"
	"github.com/yahoo/coname/keyserver/dkim"
	"github.com/yahoo/coname/keyserver/replication"
	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/vrf"
	"golang.org/x/crypto/sha3"
	"golang.org/x/net/context"
)

func (ks *Keyserver) verifyUpdateDeterministic(prevUpdate *proto.UpdateRequest, req *proto.UpdateRequest) error {
	if got, want := vrf.Compute([]byte(req.LookupParameters.UserId), ks.vrfSecret), req.Update.NewEntry.Index; !bytes.Equal(got, want) {
		return fmt.Errorf("incorrect index for user %s: got %x, expected %x", req.LookupParameters.UserId, got, want)
	}
	var prevEntry *proto.Entry
	if prevUpdate != nil {
		prevEntry = &prevUpdate.Update.NewEntry.Entry
	}
	if err := coname.VerifyUpdate(prevEntry, req.Update); err != nil {
		return err
	}
	return nil
}

func (ks *Keyserver) verifyUpdateEdge(req *proto.UpdateRequest) error {
	if len(req.Update.NewEntry.Index) != vrf.Size {
		return fmt.Errorf("index '%x' has wrong length (expected %d)", req.Update.NewEntry.Index, vrf.Size)
	}
	prevUpdate, err := ks.getUpdate(req.Update.NewEntry.Index, math.MaxUint64)
	if err != nil {
		log.Print(err)
		return fmt.Errorf("internal error")
	}
	if prevUpdate == nil { // registration: check email proof
		if !ks.insecureSkipEmailProof {
			if req.EmailProof == nil {
				return fmt.Errorf("No email proof provided")
			}

			lastAtIndex := strings.LastIndex(req.LookupParameters.UserId, "@")
			if lastAtIndex == -1 {
				return fmt.Errorf("requested user id is not a valid email address: %q", req.LookupParameters.UserId)
			}
			// determine registration type
			switch t := req.EmailProof.ProofType.(type) {
			case *proto.EmailProof_DKIMProof:
				if _, ok := ks.dkimProofAllowedDomains[req.LookupParameters.UserId[lastAtIndex+1:]]; !ok {
					return fmt.Errorf("domain not in registration whitelist: %q", req.LookupParameters.UserId[lastAtIndex+1:])

				}
				email, payload, err := dkim.CheckEmailProof(t.DKIMProof, ks.dkimProofToAddr, ks.dkimProofToAddr, ks.lookupTXT, ks.clk.Now)
				if err != nil {
					return fmt.Errorf("failed to verify DKIM proof: %s", err)
				}
				if got, want := email, req.LookupParameters.UserId; got != want {
					return fmt.Errorf("requested user ID does not match the email proof: %q != %q", got, want)
				}
				entryHash, err := base64.StdEncoding.DecodeString(payload)
				if err != nil {
					return fmt.Errorf("bad base64 in email proof: %q", payload)
				}
				var entryHashProposed [32]byte
				sha3.ShakeSum256(entryHashProposed[:], req.Update.NewEntry.Encoding)
				if !bytes.Equal(entryHashProposed[:], entryHash[:]) {
					return fmt.Errorf("email proof does not match requested entry: %s vs %s (%x)", base64.StdEncoding.EncodeToString(entryHashProposed[:]), payload, req.Update.NewEntry.Encoding)
				}

			case *proto.EmailProof_OIDCToken:
				found := false
				for _, oc := range ks.oidcProofConfig {
					if _, ok := oc.allowedDomains[req.LookupParameters.UserId[lastAtIndex+1:]]; !ok {
						continue
					}
					found = true
					email, err := oc.oidcClient.VerifyIDToken(t.OIDCToken)
					if err != nil {
						return err
					}
					if got, want := email, req.LookupParameters.UserId; got != want {
						return fmt.Errorf("requested user ID does not match the email proof: %q != %q", got, want)
					}
				}
				if !found {
					return fmt.Errorf("domain not in registration whitelist: %q", req.LookupParameters.UserId[lastAtIndex+1:])
				}
			//TODO: handle other email proof types

			default:
				return fmt.Errorf("Invalid email proof type: %T", t)
			}
		}
	}
	return ks.verifyUpdateDeterministic(prevUpdate, req)
}

type updateOutput struct {
	Epoch uint64 // which epoch the update will appear in
	Error error
}

// Update implements proto.E2EKS.UpdateServer
func (ks *Keyserver) Update(ctx context.Context, req *proto.UpdateRequest) (*proto.LookupProof, error) {
	ctx, _ = context.WithTimeout(ctx, ks.clientTimeout)
	if err := ks.verifyUpdateEdge(req); err != nil {
		return nil, err
	}

	uid := genUID()
	ch := ks.wr.Wait(uid)
	ks.log.Propose(ctx, replication.LogEntry{Data: proto.MustMarshal(&proto.KeyserverStep{
		UID:  uid,
		Type: &proto.KeyserverStep_Update{Update: req},
	})})
	select {
	case <-ctx.Done():
		ks.wr.Notify(uid, nil)
		return nil, ctx.Err()
	case v := <-ch:
		out := v.(updateOutput)
		if out.Error != nil {
			return nil, out.Error
		}
		return ks.blockingLookup(ctx, req.LookupParameters, out.Epoch)
	}
}

package server

import (
	"fmt"

	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/internal/golang.org/x/net/context"
)

func (ks *Keyserver) UpdateProfile(ctx context.Context, req *proto.SignedEntryUpdate) (*proto.LookupProof, error) {
	return nil, fmt.Errorf("UpdateProfile not implemented")
}

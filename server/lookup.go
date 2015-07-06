package server

import (
	"fmt"

	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/internal/golang.org/x/net/context"
)

func (ks *Keyserver) LookupProfile(ctx context.Context, req *proto.LookupProfileRequest) (*proto.LookupProof, error) {
	return nil, fmt.Errorf("LookupProfile not implemented")
}

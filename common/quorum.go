package common

import "github.com/yahoo/coname/proto"

// CheckQuorum evaluates whether the quorum requirement want can be satisfied
// by ratifications of the verifiers in have.
func CheckQuorum(want *proto.QuorumExpr, have map[uint64]struct{}) bool {
	if want == nil {
		return true // no requirements
	}
	var n uint32
	for _, verifier := range want.Verifiers {
		if _, yes := have[verifier]; yes {
			n++
		}
	}
	for _, e := range want.Subexpressions {
		if CheckQuorum(e, have) {
			n++
		}
	}
	return n >= want.Threshold
}

// ListQuorum inserts all verifiers mentioned in e to out. If out is nil, a new
// map is allocated.
func ListQuorum(e *proto.QuorumExpr, out map[uint64]struct{}) map[uint64]struct{} {
	if e == nil {
		return make(map[uint64]struct{}, 0)
	}
	if out == nil {
		var l int
		if e.Verifiers != nil {
			l = len(e.Verifiers)
		}
		out = make(map[uint64]struct{}, l)
	}
	for _, verifier := range e.Verifiers {
		out[verifier] = struct{}{}
	}
	for _, e := range e.Subexpressions {
		ListQuorum(e, out)
	}
	return out
}

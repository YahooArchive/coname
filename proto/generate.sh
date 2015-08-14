#!/bin/bash
# Copyright 2014-2015 The Dename Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

set -euo pipefail
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd "$DIR"

# go install ./protoc-gen-coname

protoc --coname_out=plugins=grpc:. -I . -I "$GOPATH/src/github.com/andres-erbsen/protobuf" -I "$GOPATH/src/github.com/andres-erbsen/protobuf/protobuf" *.proto

function preserve {
	sed "s/Thing/$1/g" < preserve.go.template > "$1.pr.go"
	sed "s/Thing/$1/g" < preserve_test.go.template > "$1pr_test.go"
}

preserve Profile
preserve Entry
preserve SignedEntryUpdate
preserve TimestampedEpochHead
preserve EpochHead
preserve AuthorizationPolicy

# import patched package from correct JSON output
sed -i.bak -e 's:/gogo/:/andres-erbsen/:g' *pb*.go
sed -i.bak -e 's:\bproto1\b:github_com_andres_erbsen_protobuf_proto:g' tlsconfig*pb*.go

# preserve the encoding of repeated public keys
sed -i.bak -e 's/append(m.PublicKeys, &PublicKey{})/append(m.PublicKeys, \&PublicKey_PreserveEncoding{})/' client.pb.go

# skip the text format tests (we never use the text format)
sed -i.bak -e '/Test.*Text.*testing/a\
	t.Skip()' *_test.go

rm *.pb.go.bak *_test.go.bak || true

# bound the branching factor of quorum expressions to avoid infinite recursion.
awk '{
    if ( $0 ~ /^func NewPopulatedQuorumExpr/ ) {f = 1}
    if ( f == 1 && $0 ~ /:= r\.Intn\(10\)/) { f = 0; sub(10,2,$0) }
    print($0)
}' < client.pb.go > client.pb.go.tmp && mv client.pb.go.tmp client.pb.go

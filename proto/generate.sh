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

function generateEncodedType {
	sed "s/Thing/$1/g" < encoded.go.template > "$1.pr.go"
	sed "s/Thing/$1/g" < encoded_test.go.template > "$1pr_test.go"
}

generateEncodedType Profile
generateEncodedType Entry
generateEncodedType SignedEntryUpdate
generateEncodedType TimestampedEpochHead
generateEncodedType EpochHead
generateEncodedType AuthorizationPolicy

# enable LookupProof.Entry and LookupProof.Profile to be nullable despite using a custom type
sed -i.bak -e 's/m.Entry = &Entry{}/m.Entry = \&EncodedEntry{}/' client.pb.go
sed -i.bak -e 's/m.Profile = &Profile{}/m.Profile = \&EncodedProfile{}/' client.pb.go

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

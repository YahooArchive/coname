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

go install ./protoc-gen-coname

protoc --coname_out=plugins=grpc:. -I . -I "$GOPATH/src/github.com/gogo/protobuf" *.proto
patch < less-recursion.patch

sed 's/Thing/Entry/g' < preserve.go.template > preserveEntry.go
sed 's/Thing/Entry/g' < preserve_test.go.template > preserveEntry_test.go
sed 's/Thing/SignedEntryUpdate_EntryUpdateT/g' < preserve.go.template > preserveEntryUpdate.go
sed 's/Thing/SignedEntryUpdate_EntryUpdateT/g' < preserve_test.go.template > preserveEntryUpdate_test.go
sed 's/Thing/SignedRatification_RatificationT_KeyserverStateSummary/g' < preserve.go.template > preserveKeyserverStateSummary.go
sed 's/Thing/SignedRatification_RatificationT_KeyserverStateSummary/g' < preserve_test.go.template > preserveKeyserverStateSummary_test.go
sed 's/Thing/SignedRatification_RatificationT/g' < preserve.go.template > preserveRatificationT.go
sed 's/Thing/SignedRatification_RatificationT/g' < preserve_test.go.template > preserveRatificationT_test.go

sed -i '/Test.*Text.*testing/a	t.Skip()' *_test.go

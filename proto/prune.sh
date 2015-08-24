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

cpp -P -fpreprocessed |
	grep -v 'import "gogoproto/gogo.proto";' |
	sed -r 's:^(\s*)(\S+)(\s+\S+\s*=\s*\S+).*customtype.*:\1bytes\3; // encoded \2:g' |
	sed 's: \[.*(gogoproto.*\]::g'

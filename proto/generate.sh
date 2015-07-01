#!/bin/bash
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd "$DIR"
protoc --gofast_out=plugins=grpc:. -I "$GOPATH/src" -I . *.proto

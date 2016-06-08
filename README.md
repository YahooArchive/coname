### coname [![Build Status](https://travis-ci.org/yahoo/coname.svg?branch=master)](https://travis-ci.org/yahoo/coname) [![GoDoc](https://godoc.org/github.com/yahoo/coname?status.svg)](http://godoc.org/github.com/yahoo/coname)


This repository contains a WORK-IN-PROGRESS implementation of an EXPERIMENTAL
cooperative keyserver design based on ideas from `dename`
([readme, code](https://github.com/andres-erbsen/dename),
[talk](https://media.ccc.de/browse/congress/2014/31c3_-_6597_-_en_-_saal_2_-_201412301600_-_now_i_sprinkle_thee_with_crypto_dust_-_ryan_lackey_-_andres_erbsen_-_jurre_van_bergen_-_ladar_levison_-_equinox.html#video)) and
CONIKS ([paper](https://eprint.iacr.org/2014/1004.pdf),
[code](https://github.com/coniks-sys)). NO STABILITY is offered: things that are
very likely going to change include the network protocol, the implementation,
the internal interfaces, the import path, and the name. Sometime in the future
this implementation might reach feature (and performance) parity with `dename`,
along with a CONIKS-like username privacy layer and high-availability curated
namespaces.

### development

You need a [Golang development
environment](https://golang.org/doc/install#download), a protocol buffer schema
parser (`protoc`) that [understands
protobuf3](https://github.com/google/protobuf) , [Go
protobuf3](http://www.grpc.io/docs/installation/go.html) libraries, the
[`gogoprotobuf`](https://github.com/gogo/protobuf#getting-started-give-me-the-speed-i-dont-care-about-the-rest)
code generation tool and [grpc](http://www.grpc.io/) [for
Go](https://github.com/grpc/grpc-go). On Arch Linux this comes down to `pacman
-S go`, `aura -Ak protobuf3`, `go get github.com/yahoo/coname/...
github.com/andres-erbsen/tlstestutil`.

### disclaimer

As this project includes code (from `dename`) that I wrote and released as open
source when I was employed by Google, here is a little disclaimer that I was
asked to attach to the code: `This is not a Google project.`

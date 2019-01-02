#!/bin/bash

set -euo pipefail

export PATH="$GOPATH/bin:$PATH"
RET=0

echo "Installing gometalinter..."
go get -u -t -v github.com/alecthomas/gometalinter

find . -type f -name '*.go' ! -path './vendor/*' | xargs -P 20 -n 20 gofmt -s -l > gofmt.log 2>&1 &
GOFMT_PID="$!"

# A deadline of 10m may seem excessive, but on slow machines it's preferable to allow it to take longer than to fail
# the build.
gometalinter --deadline=600s --config=./gometalinter.json --vendor ./... > metalinter_output.log 2>&1 &
METALINTER_REQUIRED_PID="$!"

echo "Waiting for required gometalinter checks to finish..."
if ! wait "$METALINTER_REQUIRED_PID"
then
    echo "Required gometalinter checks failed:"
    cat metalinter_output.log
    RET=1
fi

echo "Waiting for gofmt to finish..."
if ! wait "$GOFMT_PID" || [ -s gofmt.log ]
then
    echo "Gofmt failed:"
    cat gofmt.log
    RET=1
fi

exit "$RET"

#!/bin/bash

set -e

this_dir="$(cd $(dirname $0) && pwd)"

pushd "$this_dir"

rm -rf out
certstrap init --common-name "ca" --passphrase ""
certstrap request-cert --common-name "cert" --passphrase "" --domain "localhost"
certstrap sign cert --CA "ca"

mv -f out/* ./
rm -rf out

popd

#!/bin/bash

set -e

this_dir="$(cd $(dirname $0) && pwd)"

pushd "$this_dir"

rm -rf out
certstrap init --common-name "cacert" --passphrase ""
certstrap request-cert --common-name "cert" --passphrase ""
certstrap sign cert --CA "cacert"

mv -f out/* ./
rm -rf out

popd

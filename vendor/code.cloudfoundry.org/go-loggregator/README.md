# go-loggregator
[![GoDoc][go-doc-badge]][go-doc] [![travis][travis-badge]][travis] [![slack.cloudfoundry.org][slack-badge]][loggregator-slack]

This is a golang client library for [Loggregator][loggregator].

## Versions

At present, Loggregator supports two API versions: v1 (UDP) and v2 (gRPC).
This library provides clients for both versions.

Note that this library is also versioned. Its versions have *no* relation to
the Loggregator API.

## Usage

This repository should be imported as:

`import loggregator "code.cloudfoundry.org/go-loggregator"`

## Example

Example implementation of the client is provided in `examples/main.go`.

Build the example client by running `go build -o client main.go`

Collocate the `client` with a metron agent and set the following environment
variables: `CA_CERT_PATH`, `CERT_PATH`, `KEY_PATH`

[slack-badge]:              https://slack.cloudfoundry.org/badge.svg
[loggregator-slack]:        https://cloudfoundry.slack.com/archives/loggregator
[loggregator]:              https://github.com/cloudfoundry/loggregator
[go-doc-badge]:             https://godoc.org/code.cloudfoundry.org/go-loggregator?status.svg
[go-doc]:                   https://godoc.org/code.cloudfoundry.org/go-loggregator
[travis-badge]:             https://travis-ci.org/cloudfoundry/go-loggregator.svg?branch=master
[travis]:                   https://travis-ci.org/cloudfoundry/go-loggregator?branch=master

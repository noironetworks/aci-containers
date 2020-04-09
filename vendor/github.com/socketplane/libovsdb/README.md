libovsdb
========

[![Coverage Status](https://coveralls.io/repos/socketplane/libovsdb/badge.png?branch=master)](https://coveralls.io/r/socketplane/libovsdb?branch=master)

An OVSDB Library written in Go

## What is OVSDB?

OVSDB is the Open vSwitch Database Protocol.
It's defined in [RFC 7047](http://tools.ietf.org/html/rfc7047)
It's used mainly for managing the configuration of Open vSwitch, but it could also be used to manage your stamp collection. Philatelists Rejoice!

## Running the tests

To run integration tests, you'll need access to docker to run an Open vSwitch container.

```
docker-compose up -d

export OVS_HOST=localhost
export OVS_PORT=$(docker ps --filter "name=libovsdb_ovs_1" --format "{{.Ports}}" | sed 's/^.*:\(.*\)->.*$/\1/g')

go test -v ./...

docker-compose down
```

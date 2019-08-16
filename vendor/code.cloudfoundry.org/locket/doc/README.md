## Overview

Locket is a grpc server. golang clients can communicate with the Locket service using [LocketClient](https://godoc.org/code.cloudfoundry.org/locket/models#LocketClient). Clients in other languages can use the [.proto files](../models/locket.proto) to generate a client.

## Ifrit Runners

[Ifrit](https://github.com/tedsuo/ifrit) is a simple process model for composing single-purpose units of work into larger programs.

### Locket lock runner

Th [LockRunner](https://godoc.org/code.cloudfoundry.org/locket/lock#NewLockRunner) can be used to acquire a lock. **Note** the runner will not be ready until the lock is acquired but will exit as soon as the lock is lost.

### Locket presence runner

The [PresenceRunner](https://godoc.org/code.cloudfoundry.org/locket/lock#NewPresenceRunner) can be used to register the service presence. The only difference between a presence runner and lock runner is the presence runner will not exit when the lock is lost. Instead, it will retry to acquire the lock in the background.


## RPC Calls

Ifrit runners are the most convenient way to use the locket service. For more advanced use cases please refer to the RPC calls documented below

### LockRequest

Lock request is used to acquire a lock. A lock can be held by **one owner only**. It is not an error to acquire the lock more than once. In fact, this is required as explained below, otherwise the lock will expire. A [LockRequest](https://godoc.org/code.cloudfoundry.org/locket/models#LocketClient) is composed of the following fields:

1. `TtlInSeconds` the ttl of the lock in seconds. must be greather than `0`. the client is required to acquire the lock again before the TTL elapses, otherwise the lock will be released
2. `Resource` [**required**] a resource defines the lock and is composed of the following fields:
   1. `Key`   [**required**] the name of the lock. this can be any arbitrary name
   2. `Owner` [**required**] a unique identifier of the owner. A claimed lock can only be acquired by the same owner. Other owners will get an error
   3. `Value` [**optional**] Arbitrary metadata that can be stored with the lock
   4. `TypeCode`  [**optional**] an enum integer value that can be later used to fetch all locks by type. The [TypeCode](https://godoc.org/code.cloudfoundry.org/locket/models#TypeCode) enum currently specifies `UNKNOWN (0)`, `LOCK (1)` and `PRESENCE (2)`.
   5. `Type`  [**deprecated; optional**] a value that can be later used to fetch all locks by type. Diego currently uses `"lock"` and `"presence"`. `Type` will go away in favor of `TypeCode` in the next major release of Diego.

Returns a `LockResponse`

The following errors can be returned:

1. [ErrLockCollision](https://godoc.org/code.cloudfoundry.org/locket/models#ErrLockCollision) if the lock is already acquired by a different owner
2. [ErrInvalidTTL](https://godoc.org/code.cloudfoundry.org/locket/models#ErrInvalidTTL) if the ttl is invalid
3. [ErrInvalidOwner](https://godoc.org/code.cloudfoundry.org/locket/models#ErrInvalidOwner) if the owner is empty

**Note** other unstructured errors can be returned from the client. For example, a grpc error will returned if the client is having trouble talking to the server. Also, sql errors could be returned.

### LockResponse

The lock response is currently empty. The client will have to use the returned error to determine if the lock was successfully acquired.

### ReleaseRequest

Release a previously acquired lock. A [ReleaseRequest](https://godoc.org/code.cloudfoundry.org/locket/models#ReleaseRequest) is composed of the following fields:

1. `Resource` [**required**] a resource defines the lock and is composed of the following fields:
   1. `Key`   [**required**] the name of the lock. it must match the same value used when the lock was acquired
   2. `Owner` [**required**] a unique identifier of the owner. it must match the same value used when the lock was acquired
   3. `Value` [**not used**]
   4. `TypeCode`  [**not used**]
   5. `Type`  [**deprecated; not used**]

Returns a `ReleaseResponse`

The following errors can be returned:

1. [ErrResourceNotFound](https://godoc.org/code.cloudfoundry.org/bbs/db/sqldb/helpers#ErrResourceNotFound) will be returned if a lock with the given key wasn't found
2. [ErrLockCollision](https://godoc.org/code.cloudfoundry.org/locket/models#ErrLockCollision) if the lock is acquired by a different owner

### ReleaseResponse

The release response is currently empty. The client will have to use the returned error to determine if the lock was successfully released.

### FetchAllRequest

Fetch all acquired locks by lock type. The lock type is mandatory.  A [FetchAllRequest](https://godoc.org/code.cloudfoundry.org/locket/models#FetchAllRequest) should be passed a type field. It can be either a `TypeCode` of value `LOCK (1)` or `PRESENCE (2)`, or a `Type` string of value `lock` or `presence`. Other values of `Type` or `TypeCode` are invalid and will return an error. `Type` is deprecated and will be removed in the next major version of Diego.

1. `Type`: [**deprecated; optional**] only locks with this type will be returned in the response
2. `TypeCode`: [**optional**] only locks with this type will be returned in the response

Returns `FetchAllResponse`

Only grpc or sql errors can be returned for this request

### FetchAllResponse

A [FetchAllResponse](https://godoc.org/code.cloudfoundry.org/locket/models#FetchAllResponse) will include the following field:

1. `Resources`: an array of `Resource` objects corresponding to locks that match the `Type` or `TypeCode` specified in the `FetchAllRequest`.

### FetchRequest

Fetch a single lock by key. A [FetchRequest](https://godoc.org/code.cloudfoundry.org/locket/models#FetchRequest) is composed of the following field:

1. `Key` [**required**] the unique identifier of the lock

Returns [FetchResponse](#fetchresponse)

The following errors can be returned:

1. [ErrResourceNotFound](https://godoc.org/code.cloudfoundry.org/locket/models#ErrResourceNotFound) will be returned if a lock with the given key wasn't found

### FetchResponse

A [FetchResponse](https://godoc.org/code.cloudfoundry.org/locket/models#FetchResponse) will include the following field:

1. `Resource` the resource that was requested. A grpc error will be returned if the resource with the given key was not found.

## SQL

For a description of Locket database schema see [schema-description.md](schema-description.md)

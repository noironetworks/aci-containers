| table | column         | data type               | encrypted | description                                                                                                    |
|-------|----------------|-------------------------|-----------|----------------------------------------------------------------------------------------------------------------|
| locks | path           | character varying(255)  | NO        | Name of the lock                                                                                               |
|       | owner          | character varying(255)  | NO        | Bosh Job ID of the lock owner                                                                                  |
|       | value          | character varying(4096) | NO        | metadata set by the owner (only used by cells to store capacity information and available root-fs information) |
|       | type           | character varying(255)  | NO        | One of "lock" or "presence"                                                                                    |
|       | ttl            | bigint                  | NO        | Time to live (in seconds) of the lock                                                                          |
|       | modified_id    | character varying(255)  | NO        | GUID generated when the record is created                                                                      |
|       | modified_index | bigint                  | NO        | Integer incremented everytime there is an update to the record                                                 |

package db_test

import (
	"database/sql"
	"errors"
	"fmt"

	"code.cloudfoundry.org/bbs/db/sqldb/helpers"
	"code.cloudfoundry.org/locket/db"
	"code.cloudfoundry.org/locket/models"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func validateLockInDB(rawDB *sql.DB, res *models.Resource, expectedIndex, expectedTTL int64, expectedModifiedId string) error {
	var key, owner, value, lockType, modifiedId string
	var index, ttl int64

	lockQuery := helpers.RebindForFlavor(
		"SELECT path, owner, value, type, modified_index, ttl, modified_id FROM locks WHERE path = ?",
		dbFlavor,
	)

	row := rawDB.QueryRow(lockQuery, res.Key)
	Expect(row.Scan(&key, &owner, &value, &lockType, &index, &ttl, &modifiedId)).To(Succeed())
	errMsg := ""
	if res.Key != key {
		errMsg += fmt.Sprintf("mismatch key (%s, %s),", res.Key, key)
	}
	if res.Owner != owner {
		errMsg += fmt.Sprintf("mismatch owner (%s, %s),", res.Owner, owner)
	}
	if res.Value != value {
		errMsg += fmt.Sprintf("mismatch value (%s, %s),", res.Value, value)
	}
	if res.Type != lockType {
		errMsg += fmt.Sprintf("mismatch value (%s, %s),", res.Type, lockType)
	}
	if expectedIndex != index {
		errMsg += fmt.Sprintf("mismatch index (%d, %d),", expectedIndex, index)
	}
	if expectedTTL != ttl {
		errMsg += fmt.Sprintf("mismatch ttl (%d, %d),", expectedTTL, ttl)
	}
	if expectedModifiedId != modifiedId {
		errMsg += fmt.Sprintf("mismatch modified_id (%s, %s),", expectedModifiedId, modifiedId)
	}

	if errMsg != "" {
		return errors.New(errMsg)
	}

	return nil
}

func validateLockNotInDB(rawDB *sql.DB, res *models.Resource) error {
	lockQuery := helpers.RebindForFlavor(
		"SELECT owner FROM locks WHERE path = ?",
		dbFlavor,
	)
	var owner string
	row := rawDB.QueryRow(lockQuery, res.Key)
	err := row.Scan(&owner)
	if err != nil {
		err = sqlHelper.ConvertSQLError(err)
		if err == helpers.ErrResourceNotFound {
			return nil
		}
		return err
	}

	return fmt.Errorf("lock exists with path (%s) and owner (%s)", res.Key, owner)
}

var _ = Describe("Lock", func() {
	var resource, expectedResource *models.Resource

	BeforeEach(func() {
		resource = &models.Resource{
			Key:   "quack",
			Owner: "iamthelizardking",
			Value: "i can do anything",
			Type:  "lock",
		}
		expectedResource = &models.Resource{
			Key:      resource.Key,
			Owner:    resource.Owner,
			Value:    resource.Value,
			Type:     resource.Type,
			TypeCode: models.LOCK,
		}

		fakeGUIDProvider.NextGUIDReturns("new-guid", nil)
	})

	Context("Lock", func() {
		Context("when the lock does not exist", func() {
			Context("because the row does not exist", func() {
				Context("when the resource only has a type code", func() {
					It("inserts the lock for the owner", func() {
						typeCodeResource := &models.Resource{
							Key:      "quack",
							Owner:    "iamthelizardking",
							Value:    "i can do anything",
							TypeCode: models.LOCK,
						}
						lock, err := sqlDB.Lock(logger, typeCodeResource, 10)
						Expect(err).NotTo(HaveOccurred())
						Expect(lock).To(Equal(&db.Lock{
							Resource:      expectedResource,
							ModifiedIndex: 1,
							ModifiedId:    "new-guid",
							TtlInSeconds:  10,
						}))
						Expect(validateLockInDB(rawDB, resource, 1, 10, "new-guid")).To(Succeed())
					})
				})

				It("inserts the lock for the owner", func() {
					lock, err := sqlDB.Lock(logger, resource, 10)
					Expect(err).NotTo(HaveOccurred())
					Expect(lock).To(Equal(&db.Lock{
						Resource:      expectedResource,
						ModifiedIndex: 1,
						ModifiedId:    "new-guid",
						TtlInSeconds:  10,
					}))
					Expect(validateLockInDB(rawDB, resource, 1, 10, "new-guid")).To(Succeed())
				})

				Context("when generating a random guid fails", func() {
					BeforeEach(func() {
						fakeGUIDProvider.NextGUIDReturns("", errors.New("boom!"))
					})

					It("returns an error", func() {
						_, err := sqlDB.Lock(logger, resource, 10)
						Expect(err).To(HaveOccurred())
					})
				})
			})

			Context("because the contents of the lock are empty", func() {
				BeforeEach(func() {
					query := helpers.RebindForFlavor(
						`INSERT INTO locks (path, owner, value, modified_index) VALUES (?, ?, ?, ?);`,
						dbFlavor,
					)
					result, err := rawDB.Exec(query, resource.Key, "", "", 300)
					Expect(err).NotTo(HaveOccurred())
					Expect(result.RowsAffected()).To(BeEquivalentTo(1))
				})

				It("inserts the lock for the owner", func() {
					lock, err := sqlDB.Lock(logger, resource, 10)
					Expect(err).NotTo(HaveOccurred())
					Expect(lock).To(Equal(&db.Lock{
						Resource:      expectedResource,
						ModifiedIndex: 301,
						ModifiedId:    "new-guid",
						TtlInSeconds:  10,
					}))
					Expect(validateLockInDB(rawDB, resource, 301, 10, "new-guid")).To(Succeed())
				})
			})
		})

		Context("when the lock does exist", func() {
			BeforeEach(func() {
				_, err := sqlDB.Lock(logger, resource, 10)
				Expect(err).NotTo(HaveOccurred())
				Expect(validateLockInDB(rawDB, resource, 1, 10, "new-guid")).To(Succeed())

				fakeGUIDProvider.NextGUIDReturns("another-new-guid", nil)
			})

			Context("and the desired owner is different", func() {
				It("returns an error without grabbing the lock", func() {
					newResource := &models.Resource{
						Key:   "quack",
						Owner: "jim",
						Value: "i have never seen the princess bride and never will",
					}

					_, err := sqlDB.Lock(logger, newResource, 10)
					Expect(err).To(Equal(models.ErrLockCollision))
					Expect(validateLockInDB(rawDB, resource, 1, 10, "new-guid")).To(Succeed())
				})
			})

			Context("and the desired owner is the same", func() {
				It("increases the modified_index", func() {
					lock, err := sqlDB.Lock(logger, resource, 10)
					Expect(err).NotTo(HaveOccurred())
					Expect(lock).To(Equal(&db.Lock{
						Resource:      expectedResource,
						ModifiedIndex: 2,
						ModifiedId:    "new-guid",
						TtlInSeconds:  10,
					}))
					Expect(validateLockInDB(rawDB, resource, 2, 10, "new-guid")).To(Succeed())
				})
			})
		})

		Context("when the lock table disappear", func() {
			BeforeEach(func() {
				_, err := rawDB.Exec("DROP TABLE locks")
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				err := sqlDB.CreateLockTable(logger)
				Expect(err).NotTo(HaveOccurred())
			})

			It("returns an unrecoverable error", func() {
				_, err := sqlDB.Lock(logger, resource, 10)
				Expect(err).To(Equal(helpers.ErrUnrecoverableError))
			})
		})
	})

	Context("Release", func() {
		Context("when the lock exists", func() {
			var currentIndex, currentTTL int64

			BeforeEach(func() {
				currentIndex = 500
				currentTTL = 501
				query := helpers.RebindForFlavor(
					`INSERT INTO locks (path, owner, value, modified_index, ttl) VALUES (?, ?, ?, ?, ?);`,
					dbFlavor,
				)
				result, err := rawDB.Exec(query, resource.Key, resource.Owner, resource.Value, currentIndex, currentTTL)
				Expect(err).NotTo(HaveOccurred())
				Expect(result.RowsAffected()).To(BeEquivalentTo(1))
			})

			It("removes the lock from the lock table", func() {
				err := sqlDB.Release(logger, resource)
				Expect(err).NotTo(HaveOccurred())
				Expect(validateLockNotInDB(rawDB, resource)).To(Succeed())
			})

			Context("when the lock is owned by another owner", func() {
				It("returns an error", func() {
					err := sqlDB.Release(logger, &models.Resource{
						Key:   "quack",
						Owner: "not jim",
						Value: "beep boop",
					})
					Expect(err).To(HaveOccurred())
					Expect(err).To(MatchError(models.ErrLockCollision))
				})
			})
		})

		Context("when the lock table disappear", func() {
			BeforeEach(func() {
				_, err := rawDB.Exec("DROP TABLE locks")
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				err := sqlDB.CreateLockTable(logger)
				Expect(err).NotTo(HaveOccurred())
			})

			It("returns an error", func() {
				err := sqlDB.Release(logger, resource)
				Expect(err).To(Equal(helpers.ErrUnrecoverableError))
			})
		})

		Context("when the lock does not exist", func() {
			It("does not return an error", func() {
				err := sqlDB.Release(logger, resource)
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	Context("Fetch", func() {
		var lock, expectedLock *models.Resource

		Context("when the lock exists", func() {
			JustBeforeEach(func() {
				query := helpers.RebindForFlavor(
					`INSERT INTO locks (path, owner, value, type, modified_index, modified_id, ttl) VALUES (?, ?, ?, ?, ?, ?, ?);`,
					dbFlavor,
				)
				result, err := rawDB.Exec(query, lock.Key, lock.Owner, lock.Value, lock.Type, 434, "modified-id", 5)
				Expect(err).NotTo(HaveOccurred())
				Expect(result.RowsAffected()).To(BeEquivalentTo(1))
			})

			Context("with different types", func() {
				Context("when type unknown", func() {
					BeforeEach(func() {
						lock = &models.Resource{
							Key:   "test",
							Owner: "jim",
							Value: "locks stuff for days",
							Type:  "For Days",
						}
						expectedLock = lock
						expectedLock.TypeCode = 0
					})

					It("returns the lock from the database", func() {
						resource, err := sqlDB.Fetch(logger, "test")
						Expect(err).NotTo(HaveOccurred())
						Expect(resource).To(Equal(&db.Lock{
							Resource:      expectedLock,
							ModifiedIndex: 434,
							ModifiedId:    "modified-id",
							TtlInSeconds:  5,
						}))
					})
				})

				Context("when type known to be lock", func() {
					BeforeEach(func() {
						lock = &models.Resource{
							Key:   "test",
							Owner: "jim",
							Value: "locks stuff for days",
							Type:  "lock",
						}
						expectedLock = lock
						expectedLock.TypeCode = models.LOCK
					})

					It("returns the lock from the database", func() {
						resource, err := sqlDB.Fetch(logger, "test")
						Expect(err).NotTo(HaveOccurred())
						Expect(resource).To(Equal(&db.Lock{
							Resource:      expectedLock,
							ModifiedIndex: 434,
							ModifiedId:    "modified-id",
							TtlInSeconds:  5,
						}))
					})
				})

				Context("when type known to be presence", func() {
					BeforeEach(func() {
						lock = &models.Resource{
							Key:   "test",
							Owner: "jim",
							Value: "locks stuff for days",
							Type:  "presence",
						}
						expectedLock = lock
						expectedLock.TypeCode = models.PRESENCE
					})

					It("returns the lock from the database", func() {
						resource, err := sqlDB.Fetch(logger, "test")
						Expect(err).NotTo(HaveOccurred())
						Expect(resource).To(Equal(&db.Lock{
							Resource:      expectedLock,
							ModifiedIndex: 434,
							ModifiedId:    "modified-id",
							TtlInSeconds:  5,
						}))
					})
				})

				Context("when type code known to be lock", func() {
					BeforeEach(func() {
						lock = &models.Resource{
							Key:      "test",
							Owner:    "jim",
							Value:    "locks stuff for days",
							TypeCode: models.LOCK,
						}
						expectedLock = lock
						expectedLock.Type = models.LockType
					})

					It("returns the lock from the database", func() {
						resource, err := sqlDB.Fetch(logger, "test")
						Expect(err).NotTo(HaveOccurred())
						Expect(resource).To(Equal(&db.Lock{
							Resource:      expectedLock,
							ModifiedIndex: 434,
							ModifiedId:    "modified-id",
							TtlInSeconds:  5,
						}))
					})
				})

				Context("when type code known to be presence", func() {
					BeforeEach(func() {
						lock = &models.Resource{
							Key:      "test",
							Owner:    "jim",
							Value:    "locks stuff for days",
							TypeCode: models.PRESENCE,
						}
						expectedLock = lock
						expectedLock.Type = models.PresenceType
					})

					It("returns the lock from the database", func() {
						resource, err := sqlDB.Fetch(logger, "test")
						Expect(err).NotTo(HaveOccurred())
						Expect(resource).To(Equal(&db.Lock{
							Resource:      expectedLock,
							ModifiedIndex: 434,
							ModifiedId:    "modified-id",
							TtlInSeconds:  5,
						}))
					})
				})
			})
		})

		Context("when the lock table disappear", func() {
			BeforeEach(func() {
				_, err := rawDB.Exec("DROP TABLE locks")
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				err := sqlDB.CreateLockTable(logger)
				Expect(err).NotTo(HaveOccurred())
			})

			It("returns an error", func() {
				_, err := sqlDB.Fetch(logger, "test")
				Expect(err).To(Equal(helpers.ErrUnrecoverableError))
			})
		})

		Context("when the lock does not exist", func() {
			Context("because the row does not exist", func() {
				It("returns an resource not found error", func() {
					_, err := sqlDB.Fetch(logger, "test")
					Expect(err).To(Equal(models.ErrResourceNotFound))
				})
			})

			Context("because the contents of the lock are empty", func() {
				BeforeEach(func() {
					query := helpers.RebindForFlavor(
						`INSERT INTO locks (path, owner, value) VALUES (?, ?, ?);`,
						dbFlavor,
					)
					result, err := rawDB.Exec(query, "test", "", "")
					Expect(err).NotTo(HaveOccurred())
					Expect(result.RowsAffected()).To(BeEquivalentTo(1))
				})

				It("returns an error", func() {
					_, err := sqlDB.Fetch(logger, "test")
					Expect(err).To(Equal(models.ErrResourceNotFound))
				})
			})
		})
	})

	Context("FetchAll", func() {
		var dogLock, humanLock *db.Lock

		BeforeEach(func() {
			query := helpers.RebindForFlavor(
				`INSERT INTO locks (path, owner, value, type, modified_index, modified_id, ttl) VALUES (?, ?, ?, ?, ?, ?, ?);`,
				dbFlavor,
			)
			result, err := rawDB.Exec(query, "test1", "jake", "thedog", "dog", 10, "roof", 20)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RowsAffected()).To(BeEquivalentTo(1))

			result, err = rawDB.Exec(query, "test2", "", "", "", 10, "", 20)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RowsAffected()).To(BeEquivalentTo(1))

			result, err = rawDB.Exec(query, "test3", "finn", "thehuman", "presence", 10, "hello", 20)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RowsAffected()).To(BeEquivalentTo(1))

			dogLock = &db.Lock{
				Resource: &models.Resource{
					Key:   "test1",
					Owner: "jake",
					Value: "thedog",
					Type:  "dog",
				},
				ModifiedIndex: 10,
				ModifiedId:    "roof",
				TtlInSeconds:  20,
			}
			humanLock = &db.Lock{
				Resource: &models.Resource{
					Key:      "test3",
					Owner:    "finn",
					Value:    "thehuman",
					Type:     "presence",
					TypeCode: models.PRESENCE,
				},
				ModifiedIndex: 10,
				ModifiedId:    "hello",
				TtlInSeconds:  20,
			}
		})

		It("retrieves a list of all locks with owners", func() {
			locks, err := sqlDB.FetchAll(logger, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(locks).To(ConsistOf(dogLock, humanLock))
		})

		Context("when a type is specified", func() {
			It("filters the locks returned by that type", func() {
				locks, err := sqlDB.FetchAll(logger, "presence")
				Expect(err).NotTo(HaveOccurred())
				Expect(locks).To(ConsistOf(humanLock))
			})
		})

		Context("when the lock table disappear", func() {
			BeforeEach(func() {
				_, err := rawDB.Exec("DROP TABLE locks")
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				err := sqlDB.CreateLockTable(logger)
				Expect(err).NotTo(HaveOccurred())
			})

			It("returns an unrecoverable error", func() {
				_, err := sqlDB.FetchAll(logger, "")
				Expect(err).To(Equal(helpers.ErrUnrecoverableError))
			})
		})
	})

	Context("FetchAndRelease", func() {
		var currentIndex, currentTTL int64
		var oldLock *db.Lock
		var modifiedId string

		BeforeEach(func() {
			currentIndex = 500
			currentTTL = 501
			modifiedId = "new-guid"

			query := helpers.RebindForFlavor(
				`INSERT INTO locks (path, owner, value, modified_index, ttl, modified_id, type) VALUES (?, ?, ?, ?, ?, ?, ?);`,
				dbFlavor,
			)

			result, err := rawDB.Exec(query, resource.Key, resource.Owner, resource.Value, currentIndex, currentTTL, modifiedId, resource.Type)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RowsAffected()).To(BeEquivalentTo(1))

			oldLock, err = sqlDB.Fetch(logger, resource.Key)
			Expect(err).NotTo(HaveOccurred())
			Expect(validateLockInDB(rawDB, resource, currentIndex, currentTTL, modifiedId)).To(Succeed())
		})

		AfterEach(func() {
			query := helpers.RebindForFlavor(
				`DELETE FROM locks WHERE path = ?;`,
				dbFlavor,
			)
			_, err := rawDB.Exec(query, resource.Key)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when the lock hasn't changed", func() {
			It("deletes the lock record", func() {
				released, err := sqlDB.FetchAndRelease(logger, oldLock)
				Expect(err).NotTo(HaveOccurred())

				Expect(released).To(BeTrue())
				Expect(validateLockNotInDB(rawDB, resource)).To(Succeed())
			})
		})

		Context("when the modified index has changed", func() {
			BeforeEach(func() {
				query := helpers.RebindForFlavor(
					`UPDATE locks SET modified_index=? WHERE path = ?;`,
					dbFlavor,
				)

				result, err := rawDB.Exec(query, currentIndex+1, resource.Key)
				Expect(err).NotTo(HaveOccurred())
				Expect(result.RowsAffected()).To(BeEquivalentTo(1))
			})

			It("does not delete the lock record", func() {
				released, err := sqlDB.FetchAndRelease(logger, oldLock)
				Expect(err).To(MatchError(models.ErrLockCollision))

				Expect(released).NotTo(BeTrue())
				Expect(validateLockInDB(rawDB, resource, currentIndex+1, currentTTL, modifiedId)).To(Succeed())
			})
		})

		Context("when the modified id has changed", func() {
			BeforeEach(func() {
				query := helpers.RebindForFlavor(
					`UPDATE locks SET modified_id=? WHERE path = ?;`,
					dbFlavor,
				)

				modifiedId = "nova-guid"

				result, err := rawDB.Exec(query, modifiedId, resource.Key)
				Expect(err).NotTo(HaveOccurred())
				Expect(result.RowsAffected()).To(BeEquivalentTo(1))
			})

			It("does not delete the lock record", func() {
				released, err := sqlDB.FetchAndRelease(logger, oldLock)
				Expect(err).To(MatchError(models.ErrLockCollision))

				Expect(released).NotTo(BeTrue())
				Expect(validateLockInDB(rawDB, resource, currentIndex, currentTTL, modifiedId)).To(Succeed())
			})
		})

		Context("when the lock is owned by another owner", func() {
			BeforeEach(func() {
				query := helpers.RebindForFlavor(
					`UPDATE locks SET owner=? WHERE path = ?;`,
					dbFlavor,
				)

				result, err := rawDB.Exec(query, "danny", resource.Key)
				Expect(err).NotTo(HaveOccurred())
				Expect(result.RowsAffected()).To(BeEquivalentTo(1))
			})

			It("returns an error", func() {
				newResource := &models.Resource{
					Key:   resource.Key,
					Owner: "danny",
					Value: resource.Value,
					Type:  resource.Type,
				}

				released, err := sqlDB.FetchAndRelease(logger, oldLock)
				Expect(err).To(MatchError(models.ErrLockCollision))

				Expect(released).NotTo(BeTrue())
				Expect(validateLockInDB(rawDB, newResource, currentIndex, currentTTL, modifiedId)).To(Succeed())
			})
		})

		Context("when the lock table disappears", func() {
			BeforeEach(func() {
				_, err := rawDB.Exec("DROP TABLE locks")
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				err := sqlDB.CreateLockTable(logger)
				Expect(err).NotTo(HaveOccurred())
			})

			It("returns an error", func() {
				_, err := sqlDB.FetchAndRelease(logger, oldLock)
				Expect(err).To(Equal(helpers.ErrUnrecoverableError))
			})
		})

		Context("when the lock does not exist", func() {
			It("returns false and no error", func() {
				expired, err := sqlDB.FetchAndRelease(logger, &db.Lock{Resource: &models.Resource{Key: "meow"}})
				Expect(err).NotTo(HaveOccurred())
				Expect(expired).To(BeFalse())
			})
		})
	})

	Context("Count", func() {
		BeforeEach(func() {
			query := helpers.RebindForFlavor(
				`INSERT INTO locks (path, owner, value, type, modified_index, ttl) VALUES (?, ?, ?, ?, ?, ?);`,
				dbFlavor,
			)
			result, err := rawDB.Exec(query, "test1", "jake", "thedog", "dog", 10, 20)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RowsAffected()).To(BeEquivalentTo(1))

			result, err = rawDB.Exec(query, "test2", "", "", "", 10, 20)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RowsAffected()).To(BeEquivalentTo(1))

			result, err = rawDB.Exec(query, "test3", "finn", "thehuman", "human", 10, 20)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RowsAffected()).To(BeEquivalentTo(1))
		})

		It("retrieves a count of the locks", func() {
			count, err := sqlDB.Count(logger, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(count).To(Equal(2))
		})

		It("filters based on lock type", func() {
			count, err := sqlDB.Count(logger, "dog")
			Expect(err).NotTo(HaveOccurred())
			Expect(count).To(Equal(1))
		})

		Context("when the lock table disappear", func() {
			BeforeEach(func() {
				_, err := rawDB.Exec("DROP TABLE locks")
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				err := sqlDB.CreateLockTable(logger)
				Expect(err).NotTo(HaveOccurred())
			})

			It("returns an error", func() {
				_, err := sqlDB.Count(logger, "")
				Expect(err).To(Equal(helpers.ErrUnrecoverableError))
			})
		})
	})
})

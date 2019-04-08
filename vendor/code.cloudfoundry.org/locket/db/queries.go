package db

import "code.cloudfoundry.org/lager"

func (db *SQLDB) CreateLockTable(logger lager.Logger) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS locks (
			path VARCHAR(255) PRIMARY KEY,
			owner VARCHAR(255),
			value VARCHAR(4096),
			type VARCHAR(255) DEFAULT '',
			modified_index BIGINT DEFAULT 0,
			modified_id varchar(255) DEFAULT '',
			ttl BIGINT DEFAULT 0
		);
	`)
	if err != nil {
		return err
	}

	return nil
}

package sqldb

import (
	"context"

	"code.cloudfoundry.org/bbs/db/sqldb/helpers"
	"code.cloudfoundry.org/lager"
)

const configurationsTable = "configurations"

func (db *SQLDB) setConfigurationValue(ctx context.Context, logger lager.Logger, key, value string) error {
	return db.transact(ctx, logger, func(logger lager.Logger, tx helpers.Tx) error {
		_, err := db.upsert(
			ctx,
			logger,
			tx,
			configurationsTable,
			helpers.SQLAttributes{"value": value, "id": key},
			"id = ?", key,
		)
		if err != nil {
			logger.Error("failed-setting-config-value", err, lager.Data{"key": key})
			return err
		}

		return nil
	})
}

func (db *SQLDB) getConfigurationValue(ctx context.Context, logger lager.Logger, key string) (string, error) {
	var value string
	err := db.transact(ctx, logger, func(logger lager.Logger, tx helpers.Tx) error {
		return db.one(ctx, logger, tx, "configurations",
			helpers.ColumnList{"value"}, helpers.NoLockRow,
			"id = ?", key,
		).Scan(&value)
	})

	if err != nil {
		return "", err
	}

	return value, nil
}

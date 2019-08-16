package sqldb

import (
	"context"

	"code.cloudfoundry.org/bbs/db/sqldb/helpers"
	"code.cloudfoundry.org/bbs/models"
	"code.cloudfoundry.org/lager"
)

func (db *SQLDB) RemoveSuspectActualLRP(ctx context.Context, logger lager.Logger, lrpKey *models.ActualLRPKey) (*models.ActualLRP, error) {
	logger = logger.Session("db-remove-suspect-actual-lrp", lager.Data{"lrp_key": lrpKey})
	logger.Debug("starting")
	defer logger.Debug("complete")

	var (
		lrp *models.ActualLRP
		err error
	)

	err = db.transact(ctx, logger, func(logger lager.Logger, tx helpers.Tx) error {
		processGuid := lrpKey.ProcessGuid
		index := lrpKey.Index

		lrp, err = db.fetchActualLRPForUpdate(ctx, logger, processGuid, index, models.ActualLRP_Suspect, tx)
		if err == models.ErrResourceNotFound {
			logger.Debug("suspect-lrp-does-not-exist")
			return nil
		}

		if err != nil {
			logger.Error("failed-fetching-actual-lrp", err)
			return err
		}

		_, err = db.delete(ctx, logger, tx, "actual_lrps",
			"process_guid = ? AND instance_index = ? AND presence = ?",
			processGuid, index, models.ActualLRP_Suspect,
		)

		if err != nil {
			logger.Error("failed-delete", err)
			return models.ErrActualLRPCannotBeRemoved
		}

		return nil
	})

	return lrp, err
}

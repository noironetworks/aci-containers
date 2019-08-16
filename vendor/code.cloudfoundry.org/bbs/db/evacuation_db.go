package db

import (
	"context"

	"code.cloudfoundry.org/bbs/models"
	"code.cloudfoundry.org/lager"
)

//go:generate counterfeiter . EvacuationDB

type EvacuationDB interface {
	RemoveEvacuatingActualLRP(context.Context, lager.Logger, *models.ActualLRPKey, *models.ActualLRPInstanceKey) error
	EvacuateActualLRP(context.Context, lager.Logger, *models.ActualLRPKey, *models.ActualLRPInstanceKey, *models.ActualLRPNetInfo) (actualLRP *models.ActualLRP, err error)
}

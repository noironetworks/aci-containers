package db

import (
	"context"

	"code.cloudfoundry.org/bbs/models"
	"code.cloudfoundry.org/lager"
)

//go:generate counterfeiter . SuspectDB

type SuspectDB interface {
	RemoveSuspectActualLRP(context.Context, lager.Logger, *models.ActualLRPKey) (*models.ActualLRP, error)
}

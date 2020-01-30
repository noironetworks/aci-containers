package handlers

import (
	"net/http"

	"code.cloudfoundry.org/bbs/db"
	"code.cloudfoundry.org/bbs/models"
	"code.cloudfoundry.org/lager"
)

type ActualLRPHandler struct {
	db       db.ActualLRPDB
	exitChan chan<- struct{}
}

func NewActualLRPHandler(db db.ActualLRPDB, exitChan chan<- struct{}) *ActualLRPHandler {
	return &ActualLRPHandler{
		db:       db,
		exitChan: exitChan,
	}
}

func (h *ActualLRPHandler) ActualLRPs(logger lager.Logger, w http.ResponseWriter, req *http.Request) {
	var err error
	logger = logger.Session("actual-lrps")
	logger.Debug("starting")
	defer logger.Debug("complete")

	request := &models.ActualLRPsRequest{}
	response := &models.ActualLRPsResponse{}

	err = parseRequest(logger, req, request)
	if err == nil {
		var index *int32
		if request.IndexExists() {
			i := request.GetIndex()
			index = &i
		}
		filter := models.ActualLRPFilter{Domain: request.Domain, CellID: request.CellId, Index: index, ProcessGuid: request.ProcessGuid}
		response.ActualLrps, err = h.db.ActualLRPs(req.Context(), logger, filter)
	}

	response.Error = models.ConvertError(err)

	writeResponse(w, response)
	exitIfUnrecoverable(logger, h.exitChan, response.Error)
}

// DEPRECATED
func (h *ActualLRPHandler) ActualLRPGroups(logger lager.Logger, w http.ResponseWriter, req *http.Request) {
	var err error
	logger = logger.Session("actual-lrp-groups")

	request := &models.ActualLRPGroupsRequest{}
	response := &models.ActualLRPGroupsResponse{}
	defer func() { exitIfUnrecoverable(logger, h.exitChan, response.Error) }()
	defer writeResponse(w, response)

	err = parseRequest(logger, req, request)
	if err != nil {
		response.Error = models.ConvertError(err)
		return
	}

	filter := models.ActualLRPFilter{Domain: request.Domain, CellID: request.CellId}
	lrps, err := h.db.ActualLRPs(req.Context(), logger, filter)
	if err != nil {
		response.Error = models.ConvertError(err)
		return
	}
	response.ActualLrpGroups = models.ResolveActualLRPGroups(lrps)
}

// DEPRECATED
func (h *ActualLRPHandler) ActualLRPGroupsByProcessGuid(logger lager.Logger, w http.ResponseWriter, req *http.Request) {
	var err error
	logger = logger.Session("actual-lrp-groups-by-process-guid")

	request := &models.ActualLRPGroupsByProcessGuidRequest{}
	response := &models.ActualLRPGroupsResponse{}
	defer func() { exitIfUnrecoverable(logger, h.exitChan, response.Error) }()
	defer writeResponse(w, response)

	err = parseRequest(logger, req, request)
	if err != nil {
		response.Error = models.ConvertError(err)
		return
	}
	filter := models.ActualLRPFilter{ProcessGuid: request.ProcessGuid}
	lrps, err := h.db.ActualLRPs(req.Context(), logger, filter)
	if err != nil {
		response.Error = models.ConvertError(err)
		return
	}
	response.ActualLrpGroups = models.ResolveActualLRPGroups(lrps)
}

// DEPRECATED
func (h *ActualLRPHandler) ActualLRPGroupByProcessGuidAndIndex(logger lager.Logger, w http.ResponseWriter, req *http.Request) {
	var err error
	logger = logger.Session("actual-lrp-group-by-process-guid-and-index")

	request := &models.ActualLRPGroupByProcessGuidAndIndexRequest{}
	response := &models.ActualLRPGroupResponse{}
	defer func() { exitIfUnrecoverable(logger, h.exitChan, response.Error) }()
	defer writeResponse(w, response)

	err = parseRequest(logger, req, request)
	if err != nil {
		response.Error = models.ConvertError(err)
		return
	}
	filter := models.ActualLRPFilter{ProcessGuid: request.ProcessGuid, Index: &request.Index}
	lrps, err := h.db.ActualLRPs(req.Context(), logger, filter)

	if err == nil && len(lrps) == 0 {
		err = models.ErrResourceNotFound
	}

	if err != nil {
		response.Error = models.ConvertError(err)
		return
	}
	response.ActualLrpGroup = models.ResolveActualLRPGroup(lrps)
}

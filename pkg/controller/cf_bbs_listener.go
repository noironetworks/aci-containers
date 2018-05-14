// Copyright 2017 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"code.cloudfoundry.org/bbs"
	"code.cloudfoundry.org/bbs/events"
	"code.cloudfoundry.org/bbs/models"
	"github.com/Sirupsen/logrus"

	"github.com/noironetworks/aci-containers/pkg/cf_common"
)

type AppAndSpace struct {
	AppId    string `json:"application_id",omitempty"`
	SpaceId  string `json:"space_id",omitempty"`
	AppName  string `json:"application_name",omitempty"`
	TaskName string
}

func findRunAction(act *models.Action) *models.RunAction {
	if act == nil {
		return nil
	}
	if act.RunAction != nil {
		return act.RunAction
	}
	var newacts []*models.Action
	if act.TimeoutAction != nil {
		newacts = append(newacts, act.TimeoutAction.Action)
	} else if act.EmitProgressAction != nil {
		newacts = append(newacts, act.EmitProgressAction.Action)
	} else if act.TryAction != nil {
		newacts = append(newacts, act.TryAction.Action)
	} else if act.ParallelAction != nil && len(act.ParallelAction.Actions) > 0 {
		newacts = act.ParallelAction.Actions
	} else if act.SerialAction != nil && len(act.SerialAction.Actions) > 0 {
		newacts = act.SerialAction.Actions
	} else if act.CodependentAction != nil && len(act.CodependentAction.Actions) > 0 {
		newacts = act.CodependentAction.Actions
	}
	for _, a := range newacts {
		ra := findRunAction(a)
		if ra != nil {
			return ra
		}
	}
	return nil
}

func (env *CfEnvironment) getAppAndSpaceFromAction(action *models.Action) *AppAndSpace {
	act := findRunAction(action)
	if act != nil {
		for _, envVar := range act.Env {
			if envVar.Name == "VCAP_APPLICATION" {
				var as AppAndSpace
				err := json.Unmarshal([]byte(envVar.Value), &as)
				if err != nil {
					env.log.Error("JSON deserialize failed for VCAP_APPLICATION env var: ", err)
					return nil
				} else {
					if strings.HasPrefix(act.LogSource, "APP/TASK/") {
						as.TaskName = act.LogSource[9:]
					}
					return &as
				}
			}
		}
	}
	return nil
}

type DesiredLrp2App map[string]string
type PendingActualLrp map[string]map[string]*models.ActualLRPGroup

func (env *CfEnvironment) fetchLrps(dlrp2app DesiredLrp2App, pending PendingActualLrp) error {
	// Get all actual LRPs
	existActualGroup, err := env.bbsClient.ActualLRPGroups(env.cfLogger, models.ActualLRPFilter{})
	if err != nil {
		env.log.Error("Initial fetch of all actual LRPs failed: ", err)
		return err
	}
	env.log.Debug(fmt.Sprintf("Got %d initial BBS actual LRPs", len(existActualGroup)))

	// Get all desired LRPs
	existDesired, err := env.bbsClient.DesiredLRPs(env.cfLogger, models.DesiredLRPFilter{})
	if err != nil {
		env.log.Error("Initial fetch of all desired LRPs failed: ", err)
		return err
	}
	env.log.Debug(fmt.Sprintf("Got %d initial BBS desired LRPs", len(existDesired)))

	for _, alrpg := range existActualGroup {
		env.processBbsActualLrp(alrpg, dlrp2app, pending)
	}
	for _, dlrp := range existDesired {
		env.processBbsDesiredLrp(dlrp, dlrp2app, pending)
	}
	return nil
}

func (env *CfEnvironment) fetchTasks() error {
	tasks, err := env.bbsClient.Tasks(env.cfLogger)
	if err != nil {
		env.log.Error("Initial fetch of all tasks failed: ", err)
		return err
	}
	env.log.Debug(fmt.Sprintf("Got %d initial BBS tasks", len(tasks)))
	for _, task := range tasks {
		env.processBbsTask(task)
	}
	return nil
}

func (env *CfEnvironment) processBbsTask(task *models.Task) {
	as := env.getAppAndSpaceFromAction(task.GetAction())
	if as == nil {
		return
	}
	instIdx := cf_common.INST_IDX_STAGING
	if task.Domain == "cf-tasks" {
		instIdx = cf_common.INST_IDX_TASK
	}
	appInfo := env.constructAppInfo(as)
	cinfo := &ContainerInfo{ContainerId: task.TaskGuid,
		AppId:         appInfo.AppId,
		CellId:        task.CellId,
		InstanceIndex: instIdx,
		TaskName:      as.TaskName}

	env.indexLock.Lock()
	defer env.indexLock.Unlock()

	if env.mergeContainerInfo(cinfo) {
		env.log.Debug("BBS Task - Queuing update for container ", cinfo.ContainerId)
		env.containerUpdateQ.Add(cinfo.ContainerId)
	}
	// cinfo.IpAddress may have been updated because of mergeContainerInfo()
	appInfo.ContainerIps[cinfo.ContainerId] = cinfo.IpAddress
	if env.mergeAppInfo(appInfo, false) {
		env.log.Debug("BBS Task - Queuing update for app ", appInfo.AppId)
		env.scheduleAppAndSpaceUpdate(appInfo)
	}
}

func (env *CfEnvironment) processBbsDesiredLrp(dlrp *models.DesiredLRP,
	dlrp2app DesiredLrp2App, pending PendingActualLrp) {

	as := env.getAppAndSpaceFromAction(dlrp.GetAction())
	if as == nil {
		return
	}
	dlrp2app[dlrp.GetProcessGuid()] = as.AppId
	appInfo := env.constructAppInfo(as)
	appInfo.Instances = dlrp.Instances

	env.indexLock.Lock()
	defer env.indexLock.Unlock()
	ct_upd := make([]string, 0)
	for contId, lrp := range pending[dlrp.GetProcessGuid()] {
		inst := lrp.Instance
		if inst == nil {
			continue
		}
		cinfo := &ContainerInfo{ContainerId: contId,
			AppId:         appInfo.AppId,
			CellId:        inst.GetCellId(),
			IpAddress:     inst.GetInstanceAddress(),
			InstanceIndex: inst.GetIndex(),
			Ports:         inst.GetPorts()}
		if env.mergeContainerInfo(cinfo) {
			ct_upd = append(ct_upd, contId)
		}
		appInfo.ContainerIps[cinfo.ContainerId] = cinfo.IpAddress
	}
	delete(pending, dlrp.GetProcessGuid())

	if env.mergeAppInfo(appInfo, true) {
		env.log.Debug("BBS DesiredLRP - Queuing update for app ", appInfo.AppId)
		env.scheduleAppAndSpaceUpdate(appInfo)
	}
	for _, ct := range ct_upd {
		env.log.Debug("BBS DesiredLRP - Queuing update for container ", ct)
		env.containerUpdateQ.Add(ct)
	}
}

func (env *CfEnvironment) processBbsActualLrp(alrp *models.ActualLRPGroup,
	dlrp2app DesiredLrp2App, pending PendingActualLrp) {

	inst := alrp.Instance
	if inst == nil || inst.GetProcessGuid() == "" ||
		inst.GetInstanceGuid() == "" {
		return
	}
	appId := dlrp2app[inst.GetProcessGuid()]
	if appId == "" {
		env.log.Debug(
			fmt.Sprintf("Marked container %s as pending for Desired LRP %s",
				inst.GetInstanceGuid(), inst.GetProcessGuid()))
		alrps := pending[inst.GetProcessGuid()]
		if alrps == nil {
			alrps = make(map[string]*models.ActualLRPGroup)
		}
		alrps[inst.GetInstanceGuid()] = alrp
		pending[inst.GetProcessGuid()] = alrps
		return
	}

	env.indexLock.Lock()
	defer env.indexLock.Unlock()
	cinfo := &ContainerInfo{ContainerId: inst.GetInstanceGuid(),
		AppId:         appId,
		CellId:        inst.GetCellId(),
		IpAddress:     inst.GetInstanceAddress(),
		InstanceIndex: inst.GetIndex(),
		Ports:         inst.GetPorts()}
	cu := env.mergeContainerInfo(cinfo)

	appInfo := env.appIdx[appId]
	au := false
	if appInfo != nil && appInfo.ContainerIps[cinfo.ContainerId] != cinfo.IpAddress {
		appInfo.ContainerIps[cinfo.ContainerId] = cinfo.IpAddress
		au = true
	}

	if au {
		env.log.Debug("BBS ActualLRP - Queuing update for app ", appInfo.AppId)
		env.scheduleAppAndSpaceUpdate(appInfo)
	}
	if cu {
		env.log.Debug("BBS ActualLRP - Queuing update for container ", cinfo.ContainerId)
		env.containerUpdateQ.Add(cinfo.ContainerId)
	}
}

func (env *CfEnvironment) processContainerDelete(ctId string) {
	env.indexLock.Lock()
	defer env.indexLock.Unlock()

	cinfo := env.contIdx[ctId]
	delete(env.contIdx, ctId)
	var appInfo *AppInfo
	if cinfo != nil && cinfo.AppId != "" {
		appInfo = env.appIdx[cinfo.AppId]
		if appInfo != nil {
			delete(appInfo.ContainerIps, cinfo.ContainerId)
			env.appIdx[cinfo.AppId] = appInfo
		}
	}

	if cinfo != nil {
		env.log.Debug("BBS LRP/Task - Queuing delete for container ",
			cinfo.ContainerId)
		env.containerDeleteQ.Add(cinfo)
	}
	if appInfo != nil {
		env.log.Debug("BBS LRP/Task - Queuing update for app ", appInfo.AppId)
		env.appUpdateQ.Add(appInfo.AppId)
	}
}

type CfBbsEventListener struct {
	name         string
	bbsClient    bbs.Client
	synced       bool
	log          *logrus.Logger
	delayOnErr   time.Duration
	fetchHandler func(bbs.Client) (events.EventSource, error)
	eventHandler func(models.Event) error
}

func (l *CfBbsEventListener) Run(stopCh <-chan struct{}) {
	cancelled := false
	var es events.EventSource
	go func() {
		for !cancelled {
			var err error
			es, err = l.fetchHandler(l.bbsClient)
			if err != nil {
				l.log.Error(
					fmt.Sprintf("BBS listener %s - Error in fetch handler: ", l.name), err)
				time.Sleep(l.delayOnErr) // TODO exponential backoff
				continue
			}
			l.log.Debug(fmt.Sprintf("BBS listener %s - fetch complete", l.name))
			l.synced = true

			l.log.Debug(fmt.Sprintf("BBS listener %s - listening for events", l.name))
			for !cancelled {
				event, err := es.Next()
				if err != nil {
					if err == events.ErrUnrecognizedEventType {
						l.log.Debug(
							fmt.Sprintf("BBS listener %s - Ignoring ErrUnrecognizedEventType", l.name),
							err)
						continue
					}
					l.log.Error(fmt.Sprintf("BBS listener %s - error: ", l.name), err)
					break
				}
				if event != nil {
					l.eventHandler(event)
				}
			}
		}
		l.log.Debug(fmt.Sprintf("BBS listener %s - terminated", l.name))
	}()
	<-stopCh
	cancelled = true
	if es != nil {
		es.Close()
	}
}

func (l *CfBbsEventListener) Synced() bool {
	return l.synced
}

func NewCfBbsTaskListener(env *CfEnvironment) *CfBbsEventListener {
	fetchHandler := func(client bbs.Client) (events.EventSource, error) {
		es, err := env.bbsClient.SubscribeToTaskEvents(env.cfLogger)
		if err != nil {
			env.log.Error("Unable to subscribe to BBS Tasks: ", err)
			return nil, err
		}
		err = env.fetchTasks()
		return es, err
	}

	eventHandler := func(event models.Event) error {
		switch ev := event.(type) {
		case *models.TaskCreatedEvent:
			env.processBbsTask(ev.Task)
		case *models.TaskChangedEvent:
			env.processBbsTask(ev.After)
		case *models.TaskRemovedEvent:
			env.processContainerDelete(ev.Task.TaskGuid)
		}
		return nil
	}
	return &CfBbsEventListener{name: "Task",
		bbsClient:    env.bbsClient,
		log:          env.log,
		delayOnErr:   10 * time.Second,
		fetchHandler: fetchHandler, eventHandler: eventHandler}
}

func NewCfBbsLrpListener(env *CfEnvironment) *CfBbsEventListener {
	dlrp2app := make(DesiredLrp2App)
	pending := make(PendingActualLrp)

	fetchHandler := func(client bbs.Client) (events.EventSource, error) {
		es, err := env.bbsClient.SubscribeToEvents(env.cfLogger)
		if err != nil {
			env.log.Error("Unable to subscribe to BBS LRP events: ", err)
			return nil, err
		}
		err = env.fetchLrps(dlrp2app, pending)
		return es, err
	}

	eventHandler := func(event models.Event) error {
		switch ev := event.(type) {
		case *models.DesiredLRPCreatedEvent:
			env.processBbsDesiredLrp(ev.DesiredLrp, dlrp2app, pending)
		case *models.DesiredLRPChangedEvent:
			env.processBbsDesiredLrp(ev.After, dlrp2app, pending)
		case *models.DesiredLRPRemovedEvent:
			delete(dlrp2app, ev.DesiredLrp.GetProcessGuid())
			delete(pending, ev.DesiredLrp.GetProcessGuid())

		case *models.ActualLRPCreatedEvent:
			env.processBbsActualLrp(ev.ActualLrpGroup, dlrp2app, pending)
		case *models.ActualLRPChangedEvent:
			env.processBbsActualLrp(ev.After, dlrp2app, pending)
		case *models.ActualLRPRemovedEvent:
			if ev.ActualLrpGroup.Instance != nil {
				env.processContainerDelete(
					ev.ActualLrpGroup.Instance.GetInstanceGuid())
			}
			if ev.ActualLrpGroup.Evacuating != nil {
				env.processContainerDelete(
					ev.ActualLrpGroup.Evacuating.GetInstanceGuid())
			}
		case *models.ActualLRPCrashedEvent:
			env.processContainerDelete(ev.GetInstanceGuid())
		}
		return nil
	}
	return &CfBbsEventListener{name: "LRP",
		bbsClient:    env.bbsClient,
		log:          env.log,
		delayOnErr:   10 * time.Second,
		fetchHandler: fetchHandler, eventHandler: eventHandler}
}

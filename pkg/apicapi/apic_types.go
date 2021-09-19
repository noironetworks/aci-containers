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

package apicapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"k8s.io/client-go/util/workqueue"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

type ApicObjectBody struct {
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	Children   ApicSlice              `json:"children,omitempty"`
}

type ApicObject map[string]*ApicObjectBody

type ApicResponse struct {
	TotalCount     interface{}  `json:"totalCount"`
	SubscriptionId interface{}  `json:"subscriptionId,omitempty"`
	Imdata         []ApicObject `json:"imdata"`
}

type ApicObjectHandler func(ApicObject) bool
type ApicDnHandler func(string)

type ApicSlice []ApicObject

const ApicNameAliasLength = 64

const (
	apicSubClass = iota
	apicSubDn    = iota
	apicSubTree
)

type subscription struct {
	kind          int
	id            string
	targetClasses []string
	respClasses   []string
	targetFilter  string
	updateHook    ApicObjectHandler
	deleteHook    ApicDnHandler
}

type subIndex struct {
	subs map[string]*subscription
	ids  map[string]string
}

const (
	pendingChangeDelete = iota
	pendingChangeUpdate = iota
)

type pendingChange struct {
	kind    int
	subIds  []string
	isDirty bool
}

type ApicConnection struct {
	Apic      []string
	ApicIndex int
	user      string
	password  string
	prefix    string
	version   string // APIC version

	CachedVersion       string
	ReconnectInterval   time.Duration
	RefreshInterval     time.Duration
	RefreshTickerAdjust time.Duration
	RetryInterval       time.Duration
	SnatPbrFltrChain    bool // Configure SNAT PBR to use filter-chain
	FullSyncHook        func()

	dialer        *websocket.Dialer
	connection    *websocket.Conn
	client        *http.Client
	restartCh     chan struct{}
	subscriptions subIndex
	logger        *logrus.Logger
	log           *logrus.Entry
	signer        *signer
	token         string

	indexMutex   sync.Mutex
	syncEnabled  bool
	stopped      bool
	checkVersion bool

	desiredState       map[string]ApicSlice
	desiredStateDn     map[string]ApicObject
	keyHashes          map[string]string
	containerDns       map[string]bool
	cachedState        map[string]ApicSlice
	cacheDnSubIds      map[string]map[string]bool
	pendingSubDnUpdate map[string]pendingChange
	CachedSubnetDns    map[string]string

	deltaQueue workqueue.RateLimitingInterface
}

func (s ApicSlice) Len() int {
	return len(s)
}
func (s ApicSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (conn *ApicConnection) GetDesiredState(key string) ApicSlice {
	conn.indexMutex.Lock()
	defer conn.indexMutex.Unlock()
	return conn.desiredState[key]
}

func truncatedName(name string) string {
	nameAlias := name
	if len(name) > (ApicNameAliasLength - 1) {
		nameAlias = name[0:(ApicNameAliasLength-4)] + "..."
	}
	return nameAlias
}

func cmpAttr(a *ApicObjectBody, b *ApicObjectBody, attr string) int {
	var attra string
	var attrb string

	switch d := a.Attributes[attr].(type) {
	case string:
		attra = d
	}
	switch d := b.Attributes[attr].(type) {
	case string:
		attrb = d
	}

	return strings.Compare(attra, attrb)
}

func cmpApicObject(a ApicObject, b ApicObject) int {
	for _, bodya := range a {
		for _, bodyb := range b {
			return cmpAttr(bodya, bodyb, "dn")
		}
		break
	}
	return 0
}

func (s ApicSlice) Less(i, j int) bool {
	return cmpApicObject(s[i], s[j]) < 0
}

func (o ApicObject) GetDn() string {
	return o.GetAttrStr("dn")
}

func (o ApicObject) String() string {
	data, err := json.Marshal(&o)
	if err != nil {
		return "[invalid]"
	}
	return string(data)
}

func (o ApicObject) GetRn() string {
	for _, body := range o {
		switch r := body.Attributes["rn"].(type) {
		case string:
			return r
		}
		break
	}
	return ""
}

func (o ApicObject) BuildDn(parentDn string) string {
	dn := o.GetDn()
	if dn != "" {
		return dn
	}
	rn := o.GetRn()
	if rn != "" {
		return fmt.Sprintf("%s/%s", parentDn, rn)
	}
	return ""
}

const aciContainersAnnotKey = "aci-containers-controller-tag"
const aciContainersOwnerAnnotation = "orchestrator:aci-containers-controller"

func (o ApicObject) GetTag() string {
	for _, body := range o {
		for _, c := range body.Children {
			for class, cbody := range c {
				if class == "tagAnnotation" {
					if cbody.Attributes == nil {
						continue
					}
					switch k := cbody.Attributes["key"].(type) {
					case string:
						if k == aciContainersAnnotKey {
							switch t := cbody.Attributes["value"].(type) {
							case string:
								return t
							}
							return ""
						}
					}
				}
			}
		}
		break
	}
	return ""
}

func (o ApicObject) SetTag(tag string) {
	for _, body := range o {
		for j := len(body.Children) - 1; j >= 0; j-- {
			isTag := false
			for class, cbody := range body.Children[j] {
				if class == "tagAnnotation" {
					isTag = true
					if cbody.Attributes != nil {
						switch k := cbody.Attributes["key"].(type) {
						case string:
							if k == aciContainersAnnotKey {
								cbody.Attributes["value"] = tag
								return
							}
						}
					}
				}
			}

			if isTag {
				body.Children =
					append(body.Children[:j], body.Children[j+1:]...)
			}
		}
		break
	}

	o.AddChild(NewTagAnnotation(o.GetDn(), aciContainersAnnotKey).
		SetAttr("value", tag))
}

func (o ApicObject) SetAttr(name string, value interface{}) ApicObject {
	for _, body := range o {
		if body.Attributes == nil {
			body.Attributes = make(map[string]interface{})
		}
		body.Attributes[name] = value
		break
	}
	return o
}

func (o ApicObject) GetAttr(name string) interface{} {
	for _, body := range o {
		if body.Attributes == nil {
			return nil
		}
		return body.Attributes[name]
	}
	return nil
}

func (o ApicObject) GetAttrStr(name string) string {
	for _, body := range o {
		if body.Attributes == nil {
			return ""
		}
		switch res := body.Attributes[name].(type) {
		case string:
			return res
		default:
			return ""
		}
	}
	return ""
}

func (o ApicObject) AddChild(c ApicObject) {
	for _, body := range o {
		body.Children = append(body.Children, c)
		break
	}
}

func newApicObject(class string) ApicObject {
	attrs := make(map[string]interface{})
	for k, v := range metadata[class].attributes {
		attrs[k] = v
	}
	return ApicObject{
		class: &ApicObjectBody{Attributes: attrs},
	}
}

func EmptyApicObject(class string, dn string) ApicObject {
	attrs := map[string]interface{}{
		"dn": dn,
	}
	return ApicObject{
		class: &ApicObjectBody{Attributes: attrs},
	}
}

func (s ApicSlice) Copy() ApicSlice {
	var result ApicSlice
	for _, o := range s {
		result = append(result, o.Copy())
	}
	return result
}

func (o ApicObject) Copy() ApicObject {
	res := make(ApicObject)
	for class, body := range o {
		attrs := make(map[string]interface{})
		for k, v := range body.Attributes {
			attrs[k] = v
		}

		res[class] = &ApicObjectBody{
			Attributes: attrs,
			Children:   body.Children.Copy(),
		}
	}

	return res
}

func NewFvTenant(name string) ApicObject {
	ret := newApicObject("fvTenant")
	ret["fvTenant"].Attributes["name"] = name
	ret["fvTenant"].Attributes["dn"] =
		fmt.Sprintf("uni/tn-%s", name)
	return ret
}

func NewCloudAwsProvider(tenant, region, providerID string) ApicObject {
	ret := newApicObject("cloudAwsProvider")
	ret["cloudAwsProvider"].Attributes["region"] = region
	ret["cloudAwsProvider"].Attributes["providerId"] = providerID
	ret["cloudAwsProvider"].Attributes["dn"] =
		fmt.Sprintf("uni/tn-%s/awsprovider", tenant)
	return ret
}

func NewCloudCtxProfile(tenant, name string) ApicObject {
	ret := newApicObject("cloudCtxProfile")
	ret["cloudCtxProfile"].Attributes["name"] = name
	ret["cloudCtxProfile"].Attributes["dn"] =
		fmt.Sprintf("uni/tn-%s/ctxprofile-%s", tenant, name)
	return ret
}

func NewCloudRsToCtx(cCtxDn, ctxName string) ApicObject {
	ret := newApicObject("cloudRsToCtx")
	ret["cloudRsToCtx"].Attributes["tnFvCtxName"] = ctxName
	ret["cloudRsToCtx"].Attributes["dn"] =
		fmt.Sprintf("%s/rstoCtx", cCtxDn)
	return ret
}

func NewCloudRsCtxProfileToRegion(cCtxDn, tDn string) ApicObject {
	ret := newApicObject("cloudRsCtxProfileToRegion")
	ret["cloudRsCtxProfileToRegion"].Attributes["tDn"] = tDn
	ret["cloudRsCtxProfileToRegion"].Attributes["dn"] =
		fmt.Sprintf("%s/rsctxProfileToRegion", cCtxDn)
	return ret
}

func NewCloudCidr(cCtxDn, addr string) ApicObject {
	ret := newApicObject("cloudCidr")
	ret["cloudCidr"].Attributes["addr"] = addr
	ret["cloudCidr"].Attributes["dn"] =
		fmt.Sprintf("%s/cidr-[%s]", cCtxDn, addr)
	return ret
}

func NewCloudSubnet(cidrDn, ip string) ApicObject {
	ret := newApicObject("cloudSubnet")
	ret["cloudSubnet"].Attributes["ip"] = ip
	ret["cloudSubnet"].Attributes["dn"] =
		fmt.Sprintf("%s/subnet-[%s]", cidrDn, ip)
	return ret
}

func NewFvCtx(tenantName string, name string) ApicObject {
	ret := newApicObject("fvCtx")
	ret["fvCtx"].Attributes["name"] = name
	ret["fvCtx"].Attributes["dn"] =
		fmt.Sprintf("uni/tn-%s/ctx-%s", tenantName, name)
	return ret
}

func NewFvBD(tenantName string, name string) ApicObject {
	ret := newApicObject("fvBD")
	ret["fvBD"].Attributes["name"] = name
	ret["fvBD"].Attributes["dn"] =
		fmt.Sprintf("uni/tn-%s/BD-%s", tenantName, name)
	return ret
}

func NewCloudApp(tenantName string, name string) ApicObject {
	ret := newApicObject("cloudApp")
	ret["cloudApp"].Attributes["name"] = name
	ret["cloudApp"].Attributes["dn"] =
		fmt.Sprintf("uni/tn-%s/cloudapp-%s", tenantName, name)
	return ret
}

func NewCloudEpg(tenantName, appName, name string) ApicObject {
	ret := newApicObject("cloudEPg")
	ret["cloudEPg"].Attributes["name"] = name
	ret["cloudEPg"].Attributes["dn"] =
		fmt.Sprintf("uni/tn-%s/cloudapp-%s/cloudepg-%s", tenantName, appName, name)
	return ret
}

func NewFvSubnet(parentDn string, gwIpMask string) ApicObject {
	ret := newApicObject("fvSubnet")
	ret["fvSubnet"].Attributes["ip"] = gwIpMask
	ret["fvSubnet"].Attributes["dn"] =
		fmt.Sprintf("%s/subnet-[%s]", parentDn, gwIpMask)
	return ret
}

func NewRsCtx(parentDn string, ctx string) ApicObject {
	ret := newApicObject("fvRsCtx")
	ret["fvRsCtx"].Attributes["tnFvCtxName"] = ctx
	ret["fvRsCtx"].Attributes["dn"] =
		fmt.Sprintf("%s/rsctx", parentDn)
	return ret
}

func NewRsBdToOut(parentDn string, l3out string) ApicObject {
	ret := newApicObject("fvRsBDToOut")
	ret["fvRsBDToOut"].Attributes["tnL3extOutName"] = l3out
	ret["fvRsBDToOut"].Attributes["dn"] =
		fmt.Sprintf("%s/rsBDToOut-%s", parentDn, l3out)
	return ret
}

func NewTagInst(parentDn string, name string) ApicObject {
	ret := newApicObject("tagInst")
	ret["tagInst"].Attributes["name"] = name
	ret["tagInst"].Attributes["dn"] =
		fmt.Sprintf("%s/tag-%s", parentDn, name)
	return ret
}

func NewTagAnnotation(parentDn string, key string) ApicObject {
	dn := ""
	ret := newApicObject("tagAnnotation")
	ret["tagAnnotation"].Attributes["key"] = key
	if ApicVersion >= "4.1" {
		dn = fmt.Sprintf("%s/annotationKey-[%s]", parentDn, key)
	} else {
		dn = fmt.Sprintf("%s/annotationKey-%s", parentDn, key)
	}
	ret["tagAnnotation"].Attributes["dn"] = dn
	return ret
}

func NewHostprotPol(tenantName string, name string) ApicObject {
	ret := newApicObject("hostprotPol")
	ret["hostprotPol"].Attributes["name"] = name
	ret["hostprotPol"].Attributes["dn"] =
		fmt.Sprintf("uni/tn-%s/pol-%s", tenantName, name)
	return ret
}

func NewHostprotSubj(parentDn string, name string) ApicObject {

	ret := newApicObject("hostprotSubj")
	ret["hostprotSubj"].Attributes["name"] = name
	ret["hostprotSubj"].Attributes["dn"] =
		fmt.Sprintf("%s/subj-%s", parentDn, name)
	return ret
}

func NewHostprotRule(parentDn string, name string) ApicObject {

	ret := newApicObject("hostprotRule")
	ret["hostprotRule"].Attributes["name"] = name
	ret["hostprotRule"].Attributes["dn"] =
		fmt.Sprintf("%s/rule-%s", parentDn, name)
	return ret
}

func NewHostprotRemoteIp(parentDn string, addr string) ApicObject {

	ret := newApicObject("hostprotRemoteIp")
	ret["hostprotRemoteIp"].Attributes["addr"] = addr
	ret["hostprotRemoteIp"].Attributes["dn"] =
		fmt.Sprintf("%s/ip-[%s]", parentDn, addr)
	return ret
}

func NewQosDppPol(tenantName string, name string) ApicObject {

	ret := newApicObject("qosDppPol")
	ret["qosDppPol"].Attributes["name"] = name
	ret["qosDppPol"].Attributes["dn"] =
		fmt.Sprintf("uni/tn-%s/qosdpppol-%s", tenantName, name)
	return ret
}

func NewQosRequirement(tenantName string, name string) ApicObject {
	ret := newApicObject("qosRequirement")
	ret["qosRequirement"].Attributes["name"] = name
	ret["qosRequirement"].Attributes["dn"] =
		fmt.Sprintf("uni/tn-%s/qosreq-%s", tenantName, name)
	return ret
}

func NewRsEgressDppPol(parentDn string, dppPolName string) ApicObject {
	ret := newApicObject("qosRsEgressDppPol")
	ret["qosRsEgressDppPol"].Attributes["tnQosDppPolName"] = dppPolName
	ret["qosRsEgressDppPol"].Attributes["dn"] =
		fmt.Sprintf("%s/rsegressDppPol", parentDn)
	return ret
}

func NewRsIngressDppPol(parentDn string, dppPolName string) ApicObject {
	ret := newApicObject("qosRsIngressDppPol")
	ret["qosRsIngressDppPol"].Attributes["tnQosDppPolName"] = dppPolName
	ret["qosRsIngressDppPol"].Attributes["dn"] =
		fmt.Sprintf("%s/rsingressDppPol", parentDn)
	return ret
}

func NewQosEpDscpMarking(qosreqDn string, name string) ApicObject {
	ret := newApicObject("qosEpDscpMarking")
	ret["qosEpDscpMarking"].Attributes["name"] = name
	ret["qosEpDscpMarking"].Attributes["dn"] =
		fmt.Sprintf("%s/dscp_marking", qosreqDn)
	return ret
}

func NewVnsLDevVip(tenantName string, name string) ApicObject {
	ret := newApicObject("vnsLDevVip")
	ret["vnsLDevVip"].Attributes["name"] = name
	ret["vnsLDevVip"].Attributes["dn"] =
		fmt.Sprintf("uni/tn-%s/lDevVip-%s", tenantName, name)
	return ret
}

func NewVnsRsALDevToPhysDomP(parentDn string, physDomDn string) ApicObject {
	ret := newApicObject("vnsRsALDevToPhysDomP")
	ret["vnsRsALDevToPhysDomP"].Attributes["tDn"] = physDomDn
	ret["vnsRsALDevToPhysDomP"].Attributes["dn"] =
		fmt.Sprintf("%s/rsALDevToPhysDomP", parentDn)
	return ret
}

func NewVnsLIf(parentDn string, name string) ApicObject {
	ret := newApicObject("vnsLIf")
	ret["vnsLIf"].Attributes["name"] = name
	ret["vnsLIf"].Attributes["dn"] =
		fmt.Sprintf("%s/lIf-%s", parentDn, name)
	return ret
}

func NewVnsRsCIfAttN(parentDn string, cifDn string) ApicObject {
	ret := newApicObject("vnsRsCIfAttN")
	ret["vnsRsCIfAttN"].Attributes["tDn"] = cifDn
	ret["vnsRsCIfAttN"].Attributes["dn"] =
		fmt.Sprintf("%s/rscIfAttN-[%s]", parentDn, cifDn)
	return ret
}

func NewVnsCDev(parentDn string, name string) ApicObject {
	ret := newApicObject("vnsCDev")
	ret["vnsCDev"].Attributes["name"] = name
	ret["vnsCDev"].Attributes["dn"] =
		fmt.Sprintf("%s/cDev-%s", parentDn, name)
	return ret
}

func NewVnsCif(parentDn string, name string) ApicObject {
	ret := newApicObject("vnsCIf")
	ret["vnsCIf"].Attributes["name"] = name
	ret["vnsCIf"].Attributes["dn"] =
		fmt.Sprintf("%s/cIf-[%s]", parentDn, name)
	return ret
}

func NewVnsRsCIfPathAtt(parentDn string, pathDn string) ApicObject {
	ret := newApicObject("vnsRsCIfPathAtt")
	ret["vnsRsCIfPathAtt"].Attributes["tDn"] = pathDn
	ret["vnsRsCIfPathAtt"].Attributes["dn"] =
		fmt.Sprintf("%s/rsCIfPathAtt", parentDn)
	return ret
}

func NewVnsAbsGraph(tenantName string, name string) ApicObject {
	ret := newApicObject("vnsAbsGraph")
	ret["vnsAbsGraph"].Attributes["name"] = name
	ret["vnsAbsGraph"].Attributes["dn"] =
		fmt.Sprintf("uni/tn-%s/AbsGraph-%s", tenantName, name)
	return ret
}

func NewVnsAbsTermNodeCon(parentDn string, name string) ApicObject {
	ret := newApicObject("vnsAbsTermNodeCon")
	ret["vnsAbsTermNodeCon"].Attributes["name"] = name
	ret["vnsAbsTermNodeCon"].Attributes["dn"] =
		fmt.Sprintf("%s/AbsTermNodeCon-%s", parentDn, name)
	return ret
}

func NewVnsAbsTermNodeProv(parentDn string, name string) ApicObject {
	ret := newApicObject("vnsAbsTermNodeProv")
	ret["vnsAbsTermNodeProv"].Attributes["name"] = name
	ret["vnsAbsTermNodeProv"].Attributes["dn"] =
		fmt.Sprintf("%s/AbsTermNodeProv-%s", parentDn, name)
	return ret
}

func NewVnsAbsTermConn(parentDn string) ApicObject {
	ret := newApicObject("vnsAbsTermConn")
	ret["vnsAbsTermConn"].Attributes["dn"] =
		fmt.Sprintf("%s/AbsTConn", parentDn)
	return ret
}

func NewVnsInTerm(parentDn string) ApicObject {
	ret := newApicObject("vnsInTerm")
	ret["vnsInTerm"].Attributes["dn"] =
		fmt.Sprintf("%s/intmnl", parentDn)
	return ret
}

func NewVnsOutTerm(parentDn string) ApicObject {
	ret := newApicObject("vnsOutTerm")
	ret["vnsOutTerm"].Attributes["dn"] =
		fmt.Sprintf("%s/outtmnl", parentDn)
	return ret
}

func NewVnsAbsConnection(parentDn string, name string) ApicObject {
	ret := newApicObject("vnsAbsConnection")
	ret["vnsAbsConnection"].Attributes["name"] = name
	ret["vnsAbsConnection"].Attributes["dn"] =
		fmt.Sprintf("%s/AbsConnection-%s", parentDn, name)
	return ret
}

func NewVnsRsAbsConnectionConns(parentDn string, tDn string) ApicObject {
	ret := newApicObject("vnsRsAbsConnectionConns")
	ret["vnsRsAbsConnectionConns"].Attributes["tDn"] = tDn
	ret["vnsRsAbsConnectionConns"].Attributes["dn"] =
		fmt.Sprintf("%s/rsabsConnectionConns-[%s]", parentDn, tDn)
	return ret
}

func NewVnsAbsNode(parentDn string, name string) ApicObject {
	ret := newApicObject("vnsAbsNode")
	ret["vnsAbsNode"].Attributes["name"] = name
	ret["vnsAbsNode"].Attributes["dn"] =
		fmt.Sprintf("%s/AbsNode-%s", parentDn, name)
	return ret
}

func NewVnsAbsFuncConn(parentDn string, name string) ApicObject {
	ret := newApicObject("vnsAbsFuncConn")
	ret["vnsAbsFuncConn"].Attributes["name"] = name
	ret["vnsAbsFuncConn"].Attributes["dn"] =
		fmt.Sprintf("%s/AbsFConn-%s", parentDn, name)
	return ret
}

func NewVnsRsNodeToLDev(parentDn string, tDn string) ApicObject {
	ret := newApicObject("vnsRsNodeToLDev")
	ret["vnsRsNodeToLDev"].Attributes["tDn"] = tDn
	ret["vnsRsNodeToLDev"].Attributes["dn"] =
		fmt.Sprintf("%s/rsNodeToLDev", parentDn)
	return ret
}

func NewVnsSvcRedirectPol(tenantName string, name string) ApicObject {
	ret := newApicObject("vnsSvcRedirectPol")
	ret["vnsSvcRedirectPol"].Attributes["name"] = name
	ret["vnsSvcRedirectPol"].Attributes["dn"] =
		fmt.Sprintf("uni/tn-%s/svcCont/svcRedirectPol-%s", tenantName, name)
	ret["vnsSvcRedirectPol"].Attributes["childAction"] = "deleteAll"
	return ret
}

func NewVnsRedirectDest(parentDn string, ip string, mac string) ApicObject {
	ret := newApicObject("vnsRedirectDest")
	ret["vnsRedirectDest"].Attributes["ip"] = ip
	ret["vnsRedirectDest"].Attributes["mac"] = mac
	ret["vnsRedirectDest"].Attributes["dn"] =
		fmt.Sprintf("%s/RedirectDest_ip-[%s]", parentDn, ip)
	return ret
}

func NewFvIPSLAMonitoringPol(tenantName string, name string) ApicObject {
	ret := newApicObject("fvIPSLAMonitoringPol")
	ret["fvIPSLAMonitoringPol"].Attributes["name"] = name
	ret["fvIPSLAMonitoringPol"].Attributes["dn"] =
		fmt.Sprintf("uni/tn-%s/ipslaMonitoringPol-%s", tenantName, name)
	return ret
}

func NewVnsRsIPSLAMonitoringPol(parentDn string, tDn string) ApicObject {
	ret := newApicObject("vnsRsIPSLAMonitoringPol")
	ret["vnsRsIPSLAMonitoringPol"].Attributes["tDn"] = tDn
	ret["vnsRsIPSLAMonitoringPol"].Attributes["dn"] =
		fmt.Sprintf("%s/rsIPSLAMonitoringPol", parentDn)
	return ret
}

func NewVnsRedirectHealthGroup(tenantName string, name string) ApicObject {
	ret := newApicObject("vnsRedirectHealthGroup")
	ret["vnsRedirectHealthGroup"].Attributes["name"] = name
	ret["vnsRedirectHealthGroup"].Attributes["dn"] =
		fmt.Sprintf("uni/tn-%s/svcCont/redirectHealthGroup-%s", tenantName, name)
	return ret
}

func NewVnsRsRedirectHealthGroup(parentDn string, tDn string) ApicObject {
	ret := newApicObject("vnsRsRedirectHealthGroup")
	ret["vnsRsRedirectHealthGroup"].Attributes["tDn"] = tDn
	ret["vnsRsRedirectHealthGroup"].Attributes["dn"] =
		fmt.Sprintf("%s/rsRedirectHealthGroup", parentDn)
	return ret
}

func NewVnsLDevCtx(tenantName string, ctrctNameOrLbl string,
	graphNameOrLbl string, nodeNameOrLbl string) ApicObject {
	ret := newApicObject("vnsLDevCtx")
	ret["vnsLDevCtx"].Attributes["ctrctNameOrLbl"] = ctrctNameOrLbl
	ret["vnsLDevCtx"].Attributes["graphNameOrLbl"] = graphNameOrLbl
	ret["vnsLDevCtx"].Attributes["nodeNameOrLbl"] = nodeNameOrLbl
	ret["vnsLDevCtx"].Attributes["dn"] =
		fmt.Sprintf("uni/tn-%s/ldevCtx-c-%s-g-%s-n-%s",
			tenantName, ctrctNameOrLbl, graphNameOrLbl, nodeNameOrLbl)
	return ret
}

func NewVnsRsLDevCtxToLDev(parentDn string, tDn string) ApicObject {
	ret := newApicObject("vnsRsLDevCtxToLDev")
	ret["vnsRsLDevCtxToLDev"].Attributes["tDn"] = tDn
	ret["vnsRsLDevCtxToLDev"].Attributes["dn"] =
		fmt.Sprintf("%s/rsLDevCtxToLDev", parentDn)
	return ret
}

func NewVnsLIfCtx(parentDn string, connNameOrLbl string) ApicObject {
	ret := newApicObject("vnsLIfCtx")
	ret["vnsLIfCtx"].Attributes["connNameOrLbl"] = connNameOrLbl
	ret["vnsLIfCtx"].Attributes["dn"] =
		fmt.Sprintf("%s/lIfCtx-c-%s", parentDn, connNameOrLbl)
	return ret
}

func NewVnsRsLIfCtxToSvcRedirectPol(parentDn string, tDn string) ApicObject {
	ret := newApicObject("vnsRsLIfCtxToSvcRedirectPol")
	ret["vnsRsLIfCtxToSvcRedirectPol"].Attributes["tDn"] = tDn
	ret["vnsRsLIfCtxToSvcRedirectPol"].Attributes["dn"] =
		fmt.Sprintf("%s/rsLIfCtxToSvcRedirectPol", parentDn)
	return ret
}

func NewVnsRsLIfCtxToBD(parentDn string, tDn string) ApicObject {
	ret := newApicObject("vnsRsLIfCtxToBD")
	ret["vnsRsLIfCtxToBD"].Attributes["tDn"] = tDn
	ret["vnsRsLIfCtxToBD"].Attributes["dn"] =
		fmt.Sprintf("%s/rsLIfCtxToBD", parentDn)
	return ret
}

func NewVnsRsLIfCtxToLIf(parentDn string, tDn string) ApicObject {
	ret := newApicObject("vnsRsLIfCtxToLIf")
	ret["vnsRsLIfCtxToLIf"].Attributes["tDn"] = tDn
	ret["vnsRsLIfCtxToLIf"].Attributes["dn"] =
		fmt.Sprintf("%s/rsLIfCtxToLIf", parentDn)
	return ret
}

func NewVzBrCP(tenantName string, name string) ApicObject {
	ret := newApicObject("vzBrCP")
	ret["vzBrCP"].Attributes["name"] = name
	ret["vzBrCP"].Attributes["dn"] =
		fmt.Sprintf("uni/tn-%s/brc-%s", tenantName, name)
	return ret
}

func NewVzSubj(parentDn string, name string) ApicObject {
	ret := newApicObject("vzSubj")
	ret["vzSubj"].Attributes["name"] = name
	ret["vzSubj"].Attributes["dn"] =
		fmt.Sprintf("%s/subj-%s", parentDn, name)
	return ret
}

func NewVzInTerm(parentDn string) ApicObject {
	ret := newApicObject("vzInTerm")
	ret["vzInTerm"].Attributes["dn"] =
		fmt.Sprintf("%s/intmnl", parentDn)
	return ret
}

func NewVzOutTerm(parentDn string) ApicObject {
	ret := newApicObject("vzOutTerm")
	ret["vzOutTerm"].Attributes["dn"] =
		fmt.Sprintf("%s/outtmnl", parentDn)
	return ret
}

func NewVzRsFiltAtt(parentDn string, tnVzFilterName string) ApicObject {
	ret := newApicObject("vzRsFiltAtt")
	ret["vzRsFiltAtt"].Attributes["tnVzFilterName"] = tnVzFilterName
	ret["vzRsFiltAtt"].Attributes["dn"] =
		fmt.Sprintf("%s/rsfiltAtt-%s", parentDn, tnVzFilterName)
	return ret
}

func NewVzRsInTermGraphAtt(parentDn string, tnVnsAbsGraphName string) ApicObject {
	ret := newApicObject("vzRsInTermGraphAtt")
	ret["vzRsInTermGraphAtt"].Attributes["tnVnsAbsGraphName"] = tnVnsAbsGraphName
	ret["vzRsInTermGraphAtt"].Attributes["dn"] =
		fmt.Sprintf("%s/rsInTermGraphAtt", parentDn)
	return ret
}

func NewVzRsOutTermGraphAtt(parentDn string, tnVnsAbsGraphName string) ApicObject {
	ret := newApicObject("vzRsOutTermGraphAtt")
	ret["vzRsOutTermGraphAtt"].Attributes["tnVnsAbsGraphName"] = tnVnsAbsGraphName
	ret["vzRsOutTermGraphAtt"].Attributes["dn"] =
		fmt.Sprintf("%s/rsOutTermGraphAtt", parentDn)
	return ret
}

func NewVzRsSubjFiltAtt(parentDn string, tnVzFilterName string) ApicObject {
	ret := newApicObject("vzRsSubjFiltAtt")
	ret["vzRsSubjFiltAtt"].Attributes["tnVzFilterName"] = tnVzFilterName
	ret["vzRsSubjFiltAtt"].Attributes["dn"] =
		fmt.Sprintf("%s/rssubjFiltAtt-%s", parentDn, tnVzFilterName)
	return ret
}

func NewVzRsSubjGraphAtt(parentDn string, tnVnsAbsGraphName string) ApicObject {
	ret := newApicObject("vzRsSubjGraphAtt")
	ret["vzRsSubjGraphAtt"].Attributes["tnVnsAbsGraphName"] = tnVnsAbsGraphName
	ret["vzRsSubjGraphAtt"].Attributes["dn"] =
		fmt.Sprintf("%s/rsSubjGraphAtt", parentDn)
	return ret
}

func NewVzFilter(tenantName string, name string) ApicObject {
	ret := newApicObject("vzFilter")
	ret["vzFilter"].Attributes["name"] = name
	ret["vzFilter"].Attributes["dn"] =
		fmt.Sprintf("uni/tn-%s/flt-%s", tenantName, name)
	return ret
}

func NewVzEntry(parentDn string, name string) ApicObject {
	ret := newApicObject("vzEntry")
	ret["vzEntry"].Attributes["name"] = name
	ret["vzEntry"].Attributes["dn"] =
		fmt.Sprintf("%s/e-%s", parentDn, name)
	return ret
}

func NewL3extInstP(tenantName string, outName string, name string) ApicObject {
	ret := newApicObject("l3extInstP")
	ret["l3extInstP"].Attributes["name"] = name
	ret["l3extInstP"].Attributes["dn"] =
		fmt.Sprintf("uni/tn-%s/out-%s/instP-%s", tenantName, outName, name)
	return ret
}

func NewL3extSubnet(parentDn string, ip string) ApicObject {
	ret := newApicObject("l3extSubnet")
	ret["l3extSubnet"].Attributes["ip"] = ip
	ret["l3extSubnet"].Attributes["dn"] =
		fmt.Sprintf("%s/extsubnet-[%s]", parentDn, ip)
	return ret
}

func NewFvRsProv(parentDn string, tnVzBrCPName string) ApicObject {
	ret := newApicObject("fvRsProv")
	ret["fvRsProv"].Attributes["tnVzBrCPName"] = tnVzBrCPName
	ret["fvRsProv"].Attributes["dn"] =
		fmt.Sprintf("%s/rsprov-%s", parentDn, tnVzBrCPName)
	return ret
}

func NewFvRsCons(parentDn string, tnVzBrCPName string) ApicObject {
	ret := newApicObject("fvRsCons")
	ret["fvRsCons"].Attributes["tnVzBrCPName"] = tnVzBrCPName
	ret["fvRsCons"].Attributes["dn"] =
		fmt.Sprintf("%s/rscons-%s", parentDn, tnVzBrCPName)
	return ret
}

func NewVmmInjectedContGrp(vendor string, domain string, controller string,
	namespace string, name string) ApicObject {
	ret := newApicObject("vmmInjectedContGrp")
	ret["vmmInjectedContGrp"].Attributes["name"] = name
	ret["vmmInjectedContGrp"].Attributes["nameAlias"] = truncatedName(name)
	ret["vmmInjectedContGrp"].Attributes["dn"] =
		fmt.Sprintf("comp/prov-%s/ctrlr-[%s]-%s/injcont/ns-[%s]/grp-[%s]",
			vendor, domain, controller, namespace, name)
	return ret
}

func NewVmmInjectedDepl(vendor string, domain string, controller string,
	namespace string, name string) ApicObject {

	ret := newApicObject("vmmInjectedDepl")
	ret["vmmInjectedDepl"].Attributes["name"] = name
	ret["vmmInjectedDepl"].Attributes["nameAlias"] = truncatedName(name)
	ret["vmmInjectedDepl"].Attributes["dn"] =
		fmt.Sprintf("comp/prov-%s/ctrlr-[%s]-%s/injcont/ns-[%s]/depl-[%s]",
			vendor, domain, controller, namespace, name)
	return ret
}

func NewVmmInjectedReplSet(vendor string, domain string, controller string,
	namespace string, name string) ApicObject {

	ret := newApicObject("vmmInjectedReplSet")
	ret["vmmInjectedReplSet"].Attributes["name"] = name
	ret["vmmInjectedReplSet"].Attributes["nameAlias"] = truncatedName(name)
	ret["vmmInjectedReplSet"].Attributes["dn"] =
		fmt.Sprintf("comp/prov-%s/ctrlr-[%s]-%s/injcont/ns-[%s]/rs-[%s]",
			vendor, domain, controller, namespace, name)
	return ret
}

func NewVmmInjectedSvc(vendor string, domain string, controller string,
	namespace string, name string) ApicObject {

	ret := newApicObject("vmmInjectedSvc")
	ret["vmmInjectedSvc"].Attributes["name"] = name
	ret["vmmInjectedSvc"].Attributes["nameAlias"] = truncatedName(name)
	ret["vmmInjectedSvc"].Attributes["dn"] =
		fmt.Sprintf("comp/prov-%s/ctrlr-[%s]-%s/injcont/ns-[%s]/svc-[%s]",
			vendor, domain, controller, namespace, name)
	return ret
}

func NewVmmInjectedSvcEp(parentDn string, contGrpName string) ApicObject {
	ret := newApicObject("vmmInjectedSvcEp")
	ret["vmmInjectedSvcEp"].Attributes["contGrpName"] = contGrpName
	ret["vmmInjectedSvcEp"].Attributes["dn"] =
		fmt.Sprintf("%s/ep-%s", parentDn, contGrpName)
	return ret
}

func NewVmmInjectedSvcPort(parentDn string, port string,
	protocol string, targetPort string) ApicObject {
	ret := newApicObject("vmmInjectedSvcPort")
	port = normalizePort(port)
	targetPort = normalizePort(targetPort)
	protocol = normalizeProto(protocol)
	ret["vmmInjectedSvcPort"].Attributes["port"] = port
	ret["vmmInjectedSvcPort"].Attributes["protocol"] = protocol
	ret["vmmInjectedSvcPort"].Attributes["targetPort"] = targetPort
	ret["vmmInjectedSvcPort"].Attributes["dn"] =
		fmt.Sprintf("%s/p-%s-prot-%s-t-%s",
			parentDn, port, protocol, targetPort)
	return ret
}

func NewVmmInjectedHost(vendor string, domain string, controller string,
	name string) ApicObject {

	ret := newApicObject("vmmInjectedHost")
	ret["vmmInjectedHost"].Attributes["name"] = name
	ret["vmmInjectedHost"].Attributes["nameAlias"] = truncatedName(name)
	ret["vmmInjectedHost"].Attributes["dn"] =
		fmt.Sprintf("comp/prov-%s/ctrlr-[%s]-%s/injcont/host-[%s]",
			vendor, domain, controller, name)
	return ret
}

func NewVmmInjectedNs(vendor string, domain string, controller string,
	name string) ApicObject {

	ret := newApicObject("vmmInjectedNs")
	ret["vmmInjectedNs"].Attributes["name"] = name
	ret["vmmInjectedNs"].Attributes["nameAlias"] = truncatedName(name)
	ret["vmmInjectedNs"].Attributes["dn"] =
		fmt.Sprintf("comp/prov-%s/ctrlr-[%s]-%s/injcont/ns-[%s]",
			vendor, domain, controller, name)
	return ret
}

func NewVmmInjectedNwPol(vendor string, domain string, controller string,
	ns string, name string) ApicObject {

	ret := newApicObject("vmmInjectedNwPol")
	ret["vmmInjectedNwPol"].Attributes["name"] = name
	ret["vmmInjectedNwPol"].Attributes["nameAlias"] = truncatedName(name)
	ret["vmmInjectedNwPol"].Attributes["dn"] =
		fmt.Sprintf("comp/prov-%s/ctrlr-[%s]-%s/injcont/ns-[%s]/nwpol-[%s]",
			vendor, domain, controller, ns, name)
	return ret
}

func NewVmmInjectedOrg(vendor, domain, controller, name string) ApicObject {
	ret := newApicObject("vmmInjectedOrg")
	ret["vmmInjectedOrg"].Attributes["name"] = name
	ret["vmmInjectedOrg"].Attributes["nameAlias"] = truncatedName(name)
	ret["vmmInjectedOrg"].Attributes["dn"] =
		fmt.Sprintf("comp/prov-%s/ctrlr-[%s]-%s/injcont/org-[%s]",
			vendor, domain, controller, name)
	return ret
}

func NewVmmInjectedOrgUnit(vendor, domain, controller, org, name string) ApicObject {
	ret := newApicObject("vmmInjectedOrgUnit")
	ret["vmmInjectedOrgUnit"].Attributes["name"] = name
	ret["vmmInjectedOrgUnit"].Attributes["nameAlias"] = truncatedName(name)
	ret["vmmInjectedOrgUnit"].Attributes["dn"] =
		fmt.Sprintf("comp/prov-%s/ctrlr-[%s]-%s/injcont/org-[%s]/unit-[%s]",
			vendor, domain, controller, org, name)
	return ret
}

func NewVmmInjectedOrgUnitContGrp(vendor, domain, controller, org, unit, name string) ApicObject {
	ret := newApicObject("vmmInjectedContGrp")
	ret["vmmInjectedContGrp"].Attributes["name"] = name
	ret["vmmInjectedContGrp"].Attributes["nameAlias"] = truncatedName(name)
	ret["vmmInjectedContGrp"].Attributes["dn"] =
		fmt.Sprintf("comp/prov-%s/ctrlr-[%s]-%s/injcont/org-[%s]/unit-[%s]/grp-[%s]",
			vendor, domain, controller, org, unit, name)
	return ret
}

func NewVmmInjectedOrgUnitDepl(vendor, domain, controller, org, unit, name string) ApicObject {
	ret := newApicObject("vmmInjectedDepl")
	ret["vmmInjectedDepl"].Attributes["name"] = name
	ret["vmmInjectedDepl"].Attributes["nameAlias"] = truncatedName(name)
	ret["vmmInjectedDepl"].Attributes["dn"] =
		fmt.Sprintf("comp/prov-%s/ctrlr-[%s]-%s/injcont/org-[%s]/unit-[%s]/depl-[%s]",
			vendor, domain, controller, org, unit, name)
	return ret
}

func NewInfra(parentDn string) ApicObject {
	ret := newApicObject("infraInfra")
	ret["infraInfra"].Attributes["dn"] =
		fmt.Sprintf("%s/infra", parentDn)
	return ret
}

func NewNetflowVmmExporterPol(name string) ApicObject {
	ret := newApicObject("netflowVmmExporterPol")
	ret["netflowVmmExporterPol"].Attributes["name"] = name
	ret["netflowVmmExporterPol"].Attributes["nameAlias"] = truncatedName(name)
	ret["netflowVmmExporterPol"].Attributes["dn"] =
		fmt.Sprintf("uni/infra/vmmexporterpol-%s", name)
	return ret
}

func NewVmmVSwitchPolicyCont(domainType string, domainName string) ApicObject {
	ret := newApicObject("vmmVSwitchPolicyCont")
	ret["vmmVSwitchPolicyCont"].Attributes["dn"] =
		fmt.Sprintf("uni/vmmp-%s/dom-%s/vswitchpolcont", domainType, domainName)
	return ret
}

func NewVmmRsVswitchExporterPol(parentDn string, tDn string) ApicObject {
	ret := newApicObject("vmmRsVswitchExporterPol")
	ret["vmmRsVswitchExporterPol"].Attributes["tDn"] = tDn
	ret["vmmRsVswitchExporterPol"].Attributes["dn"] =
		fmt.Sprintf("%s/rsvswitchExporterPol-[%s]", parentDn, tDn)
	return ret
}

func NewSpanVSrcGrp(name string) ApicObject {
	ret := newApicObject("spanVSrcGrp")
	ret["spanVSrcGrp"].Attributes["name"] = name
	ret["spanVSrcGrp"].Attributes["nameAlias"] = truncatedName(name)
	ret["spanVSrcGrp"].Attributes["dn"] =
		fmt.Sprintf("uni/infra/vsrcgrp-%s", name)
	return ret
}
func NewSpanVSrc(vSourceGroup string, name string) ApicObject {
	ret := newApicObject("spanVSrc")
	ret["spanVSrc"].Attributes["name"] = name
	ret["spanVSrc"].Attributes["nameAlias"] = truncatedName(name)
	ret["spanVSrc"].Attributes["dn"] =
		fmt.Sprintf("%s/vsrc-%s", vSourceGroup, name)
	return ret
}
func NewSpanRsSrcToVPort(parentDn string, tDn string) ApicObject {
	ret := newApicObject("spanRsSrcToVPort")
	ret["spanRsSrcToVPort"].Attributes["tDn"] = tDn
	ret["spanRsSrcToVPort"].Attributes["dn"] =
		fmt.Sprintf("%s/rssrcToVPort-[%s]", parentDn, tDn)
	return ret
}
func NewSpanVDestGrp(name string) ApicObject {
	ret := newApicObject("spanVDestGrp")
	ret["spanVDestGrp"].Attributes["name"] = name
	ret["spanVDestGrp"].Attributes["nameAlias"] = truncatedName(name)
	ret["spanVDestGrp"].Attributes["dn"] =
		fmt.Sprintf("uni/infra/vdestgrp-%s", name)
	return ret
}
func NewSpanVDest(vDestGroup string, name string) ApicObject {
	ret := newApicObject("spanVDest")
	ret["spanVDest"].Attributes["name"] = name
	ret["spanVDest"].Attributes["nameAlias"] = truncatedName(name)
	ret["spanVDest"].Attributes["dn"] =
		fmt.Sprintf("%s/vdest-%s", vDestGroup, name)
	return ret
}
func NewSpanVEpgSummary(parentDn string) ApicObject {
	ret := newApicObject("spanVEpgSummary")
	ret["spanVEpgSummary"].Attributes["dn"] =
		fmt.Sprintf("%s/vepgsummary", parentDn)
	return ret
}
func NewSpanSpanLbl(vSourceGroup string, name string) ApicObject {
	ret := newApicObject("spanSpanLbl")
	ret["spanSpanLbl"].Attributes["name"] = name
	ret["spanSpanLbl"].Attributes["nameAlias"] = truncatedName(name)
	ret["spanSpanLbl"].Attributes["dn"] =
		fmt.Sprintf("%s/spanlbl-%s", vSourceGroup, name)
	return ret
}
func NewInfraAccBndlGrp(name string) ApicObject {
	ret := newApicObject("infraAccBndlGrp")
	ret["infraAccBndlGrp"].Attributes["name"] = name
	ret["infraAccBndlGrp"].Attributes["nameAlias"] = truncatedName(name)
	ret["infraAccBndlGrp"].Attributes["dn"] =
		fmt.Sprintf("uni/infra/funcprof/accbundle-%s", name)
	return ret
}
func NewInfraAccPortGrp(name string) ApicObject {
	ret := newApicObject("infraAccPortGrp")
	ret["infraAccPortGrp"].Attributes["name"] = name
	ret["infraAccPortGrp"].Attributes["nameAlias"] = truncatedName(name)
	ret["infraAccPortGrp"].Attributes["dn"] =
		fmt.Sprintf("uni/infra/funcprof/accportgrp-%s", name)
	return ret
}
func NewInfraRsSpanVSrcGrp(accBndlGrpName string, tnSpanVSrcGrpName string) ApicObject {
	ret := newApicObject("infraRsSpanVSrcGrp")
	ret["infraRsSpanVSrcGrp"].Attributes["tnSpanVSrcGrpName"] = tnSpanVSrcGrpName
	ret["infraRsSpanVSrcGrp"].Attributes["dn"] =
		fmt.Sprintf("uni/infra/funcprof/accbundle-%s/rsspanVSrcGrp-%s",
			accBndlGrpName, tnSpanVSrcGrpName)
	return ret
}
func NewInfraRsSpanVDestGrp(accBndlGrpName string, tnSpanVDestGrpName string) ApicObject {
	ret := newApicObject("infraRsSpanVDestGrp")
	ret["infraRsSpanVDestGrp"].Attributes["tnSpanVDestGrpName"] = tnSpanVDestGrpName
	ret["infraRsSpanVDestGrp"].Attributes["dn"] =
		fmt.Sprintf("uni/infra/funcprof/accbundle-%s/rsspanVDestGrp-%s",
			accBndlGrpName, tnSpanVDestGrpName)
	return ret
}
func NewInfraRsSpanVSrcGrpAP(accPortGrpName string, tnSpanVSrcGrpName string) ApicObject {
	ret := newApicObject("infraRsSpanVSrcGrp")
	ret["infraRsSpanVSrcGrp"].Attributes["tnSpanVSrcGrpName"] = tnSpanVSrcGrpName
	ret["infraRsSpanVSrcGrp"].Attributes["dn"] =
		fmt.Sprintf("uni/infra/funcprof/accportgrp-%s/rsspanVSrcGrp-%s",
			accPortGrpName, tnSpanVSrcGrpName)
	return ret
}
func NewInfraRsSpanVDestGrpAP(accPortGrpName string, tnSpanVDestGrpName string) ApicObject {
	ret := newApicObject("infraRsSpanVDestGrp")
	ret["infraRsSpanVDestGrp"].Attributes["tnSpanVDestGrpName"] = tnSpanVDestGrpName
	ret["infraRsSpanVDestGrp"].Attributes["dn"] =
		fmt.Sprintf("uni/infra/funcprof/accportgrp-%s/rsspanVDestGrp-%s",
			accPortGrpName, tnSpanVDestGrpName)
	return ret
}
func NewVmmInjectedClusterInfo(vendor string, domain string, controller string) ApicObject {
	ret := newApicObject("vmmInjectedClusterInfo")
	ret["vmmInjectedClusterInfo"].Attributes["dn"] =
		fmt.Sprintf("comp/prov-%s/ctrlr-[%s]-%s/injcont/info",
			vendor, domain, controller)
	return ret

}
func NewVmmClusterFaultInfo(parentDn string, faultCode string) ApicObject {
	ret := newApicObject("vmmClusterFaultInfo")
	ret["vmmClusterFaultInfo"].Attributes["dn"] =
		fmt.Sprintf("%s/clusterfaultinfo-%s", parentDn, faultCode)
	return ret
}
func NewVmmInjectedLabel(parentDn string, name string, value string) ApicObject {
	if name == "" {
		name = " "
	}
	if value == "" {
		value = " "
	}
	ret := newApicObject("vmmInjectedLabel")
	ret["vmmInjectedLabel"].Attributes["name"] = name
	ret["vmmInjectedLabel"].Attributes["value"] = value
	ret["vmmInjectedLabel"].Attributes["dn"] =
		fmt.Sprintf("%s/key-[%s]-val-%s", parentDn, name, value)
	return ret
}

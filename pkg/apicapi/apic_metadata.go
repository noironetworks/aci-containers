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
	"fmt"
	"strings"
)

type apicMeta struct {
	attributes map[string]interface{}
	children   []string
	normalizer func(*ApicObjectBody)
}

var portNormalizations = map[string]string{
	"0":   "unspecified",
	"20":  "ftpData",
	"25":  "smtp",
	"53":  "dns",
	"80":  "http",
	"110": "pop3",
	"443": "https",
	"554": "rtsp",
}

var classDepth = map[string]int{
	"cloudEPg":    4,
	"vzBrCP":      3,
	"vzFilter":    3,
	"hostprotPol": 3,
}

var protoNormalizations = map[string]string{
	"0":   "unspecified",
	"1":   "icmp",
	"2":   "igmp",
	"6":   "tcp",
	"8":   "egp",
	"9":   "igp",
	"17":  "udp",
	"58":  "icmpv6",
	"88":  "eigrp",
	"89":  "ospfigp",
	"103": "pim",
	"115": "l2tp",
	"132": "sctp",
}

func normalizePort(port string) string {
	if n, ok := portNormalizations[port]; ok {
		return n
	}
	return port
}

func normalizePorts(b *ApicObjectBody, ports []string) {
	if b.Attributes == nil {
		return
	}

	for _, port := range ports {
		v, ok := b.Attributes[port]
		if ok {
			switch vStr := v.(type) {
			case string:
				b.Attributes[port] = normalizePort(vStr)
			}
		}
	}
}

func normalizeProto(proto string) string {
	if n, ok := protoNormalizations[proto]; ok {
		return n
	}
	return proto
}

func redirectDestNormalizer(b *ApicObjectBody) {
	if b.Attributes == nil {
		return
	}

	v, ok := b.Attributes["mac"]
	if ok {
		switch vStr := v.(type) {
		case string:
			b.Attributes["mac"] = strings.ToUpper(vStr)
		}
	}
}

func ruleNormalizer(b *ApicObjectBody) {
	if b.Attributes == nil {
		return
	}
	normalizePorts(b, []string{"toPort", "fromPort"})

	v, ok := b.Attributes["proto"]
	if ok {
		switch vStr := v.(type) {
		case string:
			b.Attributes["proto"] = normalizeProto(vStr)
		}
	}
}

func filterEntryNormalizer(b *ApicObjectBody) {
	if b.Attributes == nil {
		return
	}

	normalizePorts(b, []string{"dToPort", "dFromPort",
		"sToPort", "sFromPort"})

	v, ok := b.Attributes["prot"]
	if ok {
		switch vStr := v.(type) {
		case string:
			b.Attributes["prot"] = normalizeProto(vStr)
		}
	}
}

func injectedSvcPortNormalizer(b *ApicObjectBody) {
	if b.Attributes == nil {
		return
	}
	normalizePorts(b, []string{"port", "nodePort"})

	v, ok := b.Attributes["protocol"]
	if ok {
		switch vStr := v.(type) {
		case string:
			b.Attributes["protocol"] = normalizeProto(vStr)
		}
	}
}

var metadata = map[string]*apicMeta{
	"fvTenant": {
		attributes: map[string]interface{}{
			"name":      "",
			"nameAlias": "",
		},
		children: []string{
			"fvBD",
			"fvCtx",
		},
	},
	"cloudAwsProvider": {
		attributes: map[string]interface{}{
			"region":          "",
			"accessKeyId":     "{{accessKeyId}}",
			"secretAccessKey": "{{secretAccessKey}}",
			"providerId":      "",
		},
		children: []string{},
	},
	"cloudDomP": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{
			"cloudBgpAsP",
			"cloudProvP",
		},
	},
	"cloudBgpAsP": {
		attributes: map[string]interface{}{
			"asn": "",
		},
		children: []string{},
	},
	"cloudProvP": {
		attributes: map[string]interface{}{
			"vendor": "",
		},
		children: []string{
			"cloudRegion",
		},
	},
	"cloudRegion": {
		attributes: map[string]interface{}{
			"name":    "",
			"adminSt": "managed",
		},
		children: []string{},
	},
	"cloudCtxProfile": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{
			"cloudRsToCtx",
			"cloudRsCtxProfileToRegion",
			"cloudCidr",
		},
	},
	"cloudRsToCtx": {
		attributes: map[string]interface{}{
			"tnFvCtxName": "",
		},
		children: []string{},
	},
	"cloudRsCtxProfileToRegion": {
		attributes: map[string]interface{}{
			"tDn": "",
		},
		children: []string{},
	},
	"cloudCidr": {
		attributes: map[string]interface{}{
			"addr":    "",
			"primary": "yes",
		},
		children: []string{
			"cloudSubnet",
		},
	},
	"cloudSubnet": {
		attributes: map[string]interface{}{
			"ip":    "",
			"scope": "shared,public",
		},
		children: []string{},
	},
	"fvCtx": {
		attributes: map[string]interface{}{
			"name":      "",
			"nameAlias": "",
			"pcEnfPref": "enforced",
		},
		children: []string{
			"fvRtCtx",
		},
	},
	"fvAp": {
		attributes: map[string]interface{}{
			"name":      "",
			"nameAlias": "",
		},
		children: []string{
			"fvAEPg",
		},
	},
	"cloudApp": {
		attributes: map[string]interface{}{
			"name":      "",
			"nameAlias": "",
		},
		children: []string{
			"cloudEPg",
		},
	},
	"fvAEPg": {
		attributes: map[string]interface{}{
			"name":      "",
			"nameAlias": "",
		},
		children: []string{
			"fvRsBd",
			"fvRsCons",
			"fvRsProv",
		},
	},
	"cloudEPg": {
		attributes: map[string]interface{}{
			"name":      "",
			"nameAlias": "",
		},
		children: []string{
			"fvRsCons",
			"fvRsProv",
		},
	},
	"cloudEPSelector": {
		attributes: map[string]interface{}{
			"name":            "",
			"matchExpression": "",
		},
		children: []string{},
	},
	"fvRsBd": {
		attributes: map[string]interface{}{
			"name":       "",
			"nameAlias":  "",
			"tCl":        "fvBD",
			"tDn":        "",
			"tRn":        "",
			"tType":      "name",
			"tnFvBDName": "",
		},
		children: []string{
			"fvRsBd",
			"fvRsCons",
			"fvRsProv",
		},
	},
	"fvBD": {
		attributes: map[string]interface{}{
			"arpFlood":       "no",
			"ipLearning":     "yes",
			"name":           "",
			"nameAlias":      "",
			"unicastRoute":   "yes",
			"unkMacUcastAct": "proxy",
		},
		children: []string{
			"fvSubnet",
			"fvRsCtx",
			"fvRsBDToOut",
		},
	},
	"fvRsCtx": {
		attributes: map[string]interface{}{
			"tnFvCtxName": "",
		},
	},
	"fvRsBDToOut": {
		attributes: map[string]interface{}{
			"tnL3extOutName": "",
		},
	},
	"fvSubnet": {
		attributes: map[string]interface{}{
			"ip":        "",
			"virtual":   "no",
			"preferred": "no",
		},
	},
	"tagInst": {
		attributes: map[string]interface{}{
			"name": "",
		},
	},
	"tagAnnotation": {
		attributes: map[string]interface{}{
			"key": "",
		},
	},
	"hostprotPol": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{
			"hostprotSubj",
		},
	},
	"hostprotSubj": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{
			"hostprotRule",
		},
	},
	"hostprotRule": {
		attributes: map[string]interface{}{
			"name":      "",
			"connTrack": "reflexive",
			"direction": "ingress",
			"ethertype": "undefined",
			"protocol":  "unspecified",
			"fromPort":  "unspecified",
			"toPort":    "unspecified",
		},
		children: []string{
			"hostprotRule",
		},
		normalizer: ruleNormalizer,
	},
	"hostprotDnsName": {
		attributes: map[string]interface{}{
			"name": "",
		},
	},
	"hostprotRemoteIp": {
		attributes: map[string]interface{}{
			"addr": "",
		},
	},
	"qosRequirement": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{
			"qosRsEgressDppPol",
			"qosRsIngressDppPol",
			"qosEpDscpMarking",
		},
	},
	"qosRsEgressDppPol": {
		attributes: map[string]interface{}{
			"tnQosDppPolName": "",
		},
	},
	"qosRsIngressDppPol": {
		attributes: map[string]interface{}{
			"tnQosDppPolName": "",
		},
	},
	"qosDppPol": {
		attributes: map[string]interface{}{
			"name":      "",
			"burst":     "unspecified",
			"burstUnit": "kilo",
			"rate":      "0",
			"rateUnit":  "kilo",
		},
	},
	"qosEpDscpMarking": {
		attributes: map[string]interface{}{
			"mark": "",
		},
	},
	"vnsLDevVip": {
		attributes: map[string]interface{}{
			"name":         "",
			"devtype":      "PHYSICAL",
			"svcType":      "OTHERS",
			"contextAware": "single-Context",
			"managed":      "yes",
		},
		children: []string{
			"vnsRsALDevToPhysDomP",
			"vnsLIf",
			"vnsCDev",
		},
	},
	"vnsRsALDevToPhysDomP": {
		attributes: map[string]interface{}{
			"tDn": "",
		},
	},
	"vnsLIf": {
		attributes: map[string]interface{}{
			"name":  "",
			"encap": "",
		},
		children: []string{
			"vnsRsCIfAttN",
		},
	},
	"vnsRsCIfAttN": {
		attributes: map[string]interface{}{
			"tDn": "",
		},
	},
	"vnsCDev": {
		attributes: map[string]interface{}{
			"name":      "",
			"devCtxLbl": "",
		},
		children: []string{
			"vnsCIf",
		},
	},
	"vnsCIf": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{
			"vnsRsCIfPathAtt",
		},
	},
	"vnsRsCIfPathAtt": {
		attributes: map[string]interface{}{
			"tDn": "",
		},
	},
	"vnsAbsGraph": {
		attributes: map[string]interface{}{
			"name":           "",
			"uiTemplateType": "UNSPECIFIED",
		},
		children: []string{
			"vnsAbsTermNodeCon",
			"vnsAbsTermNodeProv",
			"vnsAbsConnection",
			"vnsAbsNode",
		},
	},
	"vnsAbsTermNodeCon": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{
			"vnsAbsTermConn",
			"vnsInTerm",
			"vnsOutTerm",
		},
	},
	"vnsAbsTermNodeProv": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{
			"vnsAbsTermConn",
			"vnsInTerm",
			"vnsOutTerm",
		},
	},
	"vnsAbsTermConn": {
		attributes: map[string]interface{}{},
	},
	"vnsInTerm": {
		attributes: map[string]interface{}{},
	},
	"vnsOutTerm": {
		attributes: map[string]interface{}{},
	},
	"vnsAbsConnection": {
		attributes: map[string]interface{}{
			"name":          "",
			"adjType":       "L3",
			"connDir":       "unknown",
			"connType":      "external",
			"directConnect": "no",
			"unicastRoute":  "yes",
		},
		children: []string{
			"vnsRsAbsConnectionConns",
		},
	},
	"vnsRsAbsConnectionConns": {
		attributes: map[string]interface{}{
			"tDn": "",
		},
	},
	"vnsAbsNode": {
		attributes: map[string]interface{}{
			"name":             "",
			"funcTemplateType": "OTHER",
			"funcType":         "GoTo",
			"isCopy":           "no",
			"managed":          "yes",
			"routingMode":      "unspecified",
			"shareEncap":       "no",
		},
		children: []string{
			"vnsAbsFuncConn",
			"vnsRsNodeToLDev",
		},
	},
	"vnsAbsFuncConn": {
		attributes: map[string]interface{}{
			"name": "",
		},
	},
	"vnsRsNodeToLDev": {
		attributes: map[string]interface{}{
			"tDn": "",
		},
	},
	"vnsSvcRedirectPol": {
		attributes: map[string]interface{}{
			"name":                "",
			"thresholdDownAction": "permit",
		},
		children: []string{
			"vnsRedirectDest",
			"vnsRsIPSLAMonitoringPol",
		},
	},
	"vnsRedirectDest": {
		attributes: map[string]interface{}{
			"ip":    "",
			"mac":   "",
			"descr": "",
		},
		normalizer: redirectDestNormalizer,
		children: []string{
			"vnsRsRedirectHealthGroup",
		},
	},
	"fvIPSLAMonitoringPol": {
		attributes: map[string]interface{}{
			"name":         "",
			"slaType":      "icmp",
			"slaFrequency": "60",
		},
	},
	"vnsRsIPSLAMonitoringPol": {
		attributes: map[string]interface{}{
			"tDn": "",
		},
	},
	"vnsRedirectHealthGroup": {
		attributes: map[string]interface{}{
			"name": "",
		},
	},
	"vnsRsRedirectHealthGroup": {
		attributes: map[string]interface{}{
			"tDn": "",
		},
	},
	"vnsLDevCtx": {
		attributes: map[string]interface{}{
			"ctrctNameOrLbl": "",
			"graphNameOrLbl": "",
			"nodeNameOrLbl":  "",
		},
		children: []string{
			"vnsRsLDevCtxToLDev",
			"vnsLIfCtx",
		},
	},
	"vnsRsLDevCtxToLDev": {
		attributes: map[string]interface{}{
			"tDn": "",
		},
	},
	"vnsLIfCtx": {
		attributes: map[string]interface{}{
			"connNameOrLbl": "",
		},
		children: []string{
			"vnsRsLIfCtxToSvcRedirectPol",
			"vnsRsLIfCtxToBD",
			"vnsRsLIfCtxToLIf",
		},
	},
	"vnsRsLIfCtxToSvcRedirectPol": {
		attributes: map[string]interface{}{
			"tDn": "",
		},
	},
	"vnsRsLIfCtxToBD": {
		attributes: map[string]interface{}{
			"tDn": "",
		},
	},
	"vnsRsLIfCtxToLIf": {
		attributes: map[string]interface{}{
			"tDn": "",
		},
	},
	"vzBrCP": {
		attributes: map[string]interface{}{
			"name":  "",
			"scope": "context",
		},
		children: []string{
			"vzSubj",
		},
	},
	"vzSubj": {
		attributes: map[string]interface{}{
			"name":        "",
			"revFltPorts": "yes",
		},
		children: []string{
			"vzRsSubjFiltAtt",
			"vzRsSubjGraphAtt",
			"vzInTerm",
			"vzOutTerm",
		},
	},
	"vzInTerm": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{
			"vzRsFiltAtt",
			"vzRsInTermGraphAtt",
		},
	},
	"vzOutTerm": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{
			"vzRsFiltAtt",
			"vzRsOutTermGraphAtt",
		},
	},
	"vzRsInTermGraphAtt": {
		attributes: map[string]interface{}{
			"tnVnsAbsGraphName": "",
		},
	},
	"vzRsOutTermGraphAtt": {
		attributes: map[string]interface{}{
			"tnVnsAbsGraphName": "",
		},
	},
	"vzRsFiltAtt": {
		attributes: map[string]interface{}{
			"tnVzFilterName": "",
		},
	},
	"vzRsSubjFiltAtt": {
		attributes: map[string]interface{}{
			"tnVzFilterName": "",
		},
	},
	"vzRsSubjGraphAtt": {
		attributes: map[string]interface{}{
			"tnVnsAbsGraphName": "",
		},
	},
	"vzFilter": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{
			"vzEntry",
		},
	},
	"vzEntry": {
		attributes: map[string]interface{}{
			"name":        "",
			"applyToFrag": "no",
			"arpOpc":      "unspecified",
			"dFromPort":   "unspecified",
			"dToPort":     "unspecified",
			"etherT":      "unspecified",
			"prot":        "unspecified",
			"sFromPort":   "unspecified",
			"sToPort":     "unspecified",
			"tcpRules":    "",
			"stateful":    "no",
		},
		normalizer: filterEntryNormalizer,
	},
	"l3extInstP": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{
			"l3extSubnet",
			"fvRsProv",
			"fvRsCons",
		},
	},
	"l3extSubnet": {
		attributes: map[string]interface{}{
			"ip":    "",
			"scope": "import-security",
		},
	},
	"fvRsProv": {
		attributes: map[string]interface{}{
			"tnVzBrCPName": "",
		},
	},
	"fvRsCons": {
		attributes: map[string]interface{}{
			"tnVzBrCPName": "",
		},
	},
	"vmmInjectedContGrp": {
		attributes: map[string]interface{}{
			"guid":            "",
			"name":            "",
			"replicaSetName":  "",
			"hostName":        "",
			"computeNodeName": "",
		},
		children: []string{
			"vmmInjectedLabel",
		},
	},
	"vmmInjectedDepl": {
		attributes: map[string]interface{}{
			"guid":     "",
			"name":     "",
			"replicas": "",
		},
		children: []string{
			"vmmInjectedLabel",
		},
	},
	"vmmInjectedReplSet": {
		attributes: map[string]interface{}{
			"guid":           "",
			"name":           "",
			"deploymentName": "",
		},
		children: []string{
			"vmmInjectedLabel",
		},
	},
	"vmmInjectedSvc": {
		attributes: map[string]interface{}{
			"guid":      "",
			"name":      "",
			"clusterIp": "0.0.0.0",
			"lbIp":      "0.0.0.0",
			"type":      "clusterUp",
		},
		children: []string{
			"vmmInjectedSvcEp",
			"vmmInjectedSvcPort",
			"vmmInjectedLabel",
		},
	},
	"vmmInjectedSvcEp": {
		attributes: map[string]interface{}{
			"name":        "",
			"contGrpName": "",
		},
	},
	"vmmInjectedSvcPort": {
		attributes: map[string]interface{}{
			"protocol":   "",
			"port":       "",
			"nodePort":   "",
			"targetPort": "",
		},
		normalizer: injectedSvcPortNormalizer,
	},
	"vmmInjectedHost": {
		attributes: map[string]interface{}{
			"name":      "",
			"hostName":  "",
			"kernelVer": "",
			"os":        "",
		},
	},
	"vmmInjectedNs": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{
			"vmmInjectedContGrp",
			"vmmInjectedSvc",
			"vmmInjectedDepl",
			"vmmInjectedReplSet",
			"vmmInjectedLabel",
		},
	},
	"vmmInjectedNwPol": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{},
	},
	"vmmInjectedOrg": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{
			"vmmInjectedOrgUnit",
		},
	},
	"vmmInjectedOrgUnit": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{
			"vmmInjectedContGrp",
			"vmmInjectedDepl",
		},
	},
	"infraInfra": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{
			"netflowVmmExporterPol",
			"spanVSrcGrp",
			"spanVDestGrp",
			"infraAccBndlGrp",
			"infraAccPortGrp",
		},
	},
	"netflowVmmExporterPol": {
		attributes: map[string]interface{}{
			"name":    "",
			"ver":     "v5",
			"dstAddr": "",
			"dstPort": "2055",
		},
		children: []string{},
	},
	"vmmVSwitchPolicyCont": {
		attributes: map[string]interface{}{},
		children: []string{
			"vmmRsVswitchExporterPol",
		},
	},
	"vmmRsVswitchExporterPol": {
		attributes: map[string]interface{}{
			"tDn":               "",
			"activeFlowTimeOut": "60",
			"idleFlowTimeOut":   "15",
			"samplingRate":      "0",
		},
		children: []string{},
	},
	"spanVSrcGrp": {
		attributes: map[string]interface{}{
			"name":    "",
			"adminSt": "start",
		},
		children: []string{
			"spanVSrc",
			"spanSpanLbl",
		},
	},
	"spanVSrc": {
		attributes: map[string]interface{}{
			"name": "",
			"dir":  "both",
		},
		children: []string{
			"spanRsSrcToVPort",
		},
	},
	"spanRsSrcToVPort": {
		attributes: map[string]interface{}{
			"tDn": "",
		},
		children: []string{},
	},
	"spanVDestGrp": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{
			"spanVDest",
		},
	},
	"spanVDest": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{
			"spanVEpgSummary",
		},
	},
	"spanVEpgSummary": {
		attributes: map[string]interface{}{
			"dstIp":  "",
			"flowId": "1",
		},
		children: []string{},
	},
	"spanSpanLbl": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{},
	},
	"infraAccBndlGrp": {
		attributes: map[string]interface{}{
			"name": "",
			"lagT": "node",
		},
		children: []string{
			"infraRsSpanVSrcGrp",
			"infraRsSpanVDestGrp",
		},
	},
	"infraAccPortGrp": {
		attributes: map[string]interface{}{
			"name": "",
		},
		children: []string{
			"infraRsSpanVSrcGrp",
			"infraRsSpanVDestGrp",
		},
	},
	"infraRsSpanVSrcGrp": {
		attributes: map[string]interface{}{
			"tnSpanVSrcGrpName": "",
		},
		children: []string{},
	},
	"infraRsSpanVDestGrp": {
		attributes: map[string]interface{}{
			"tnSpanVDestGrpName": "",
		},
		children: []string{},
	},
	"vmmInjectedClusterInfo": {
		attributes: map[string]interface{}{
			"accountName": "",
			"version":     "",
			"provider":    "",
		},
		children: []string{
			"vmmnInjectedClusterDetails",
			"vmmInjectedClusterSubnet",
			"vmmClusterFaultInfo",
		},
	},
	"vmmClusterFaultInfo": {
		attributes: map[string]interface{}{
			"faultDesc":     "",
			"faultSeverity": "",
			"faultCode":     "",
		},
	},
	"vmmInjectedLabel": {
		attributes: map[string]interface{}{
			"name":  "",
			"value": "",
		},
	},
}

func AddMetaDataChild(parent, child string) error {
	p := metadata[parent]
	if p == nil {
		return fmt.Errorf("parent %s not found", parent)
	}

	c := metadata[child]
	if c == nil {
		return fmt.Errorf("child %s not found", child)
	}

	p.children = append(p.children, child)
	return nil
}

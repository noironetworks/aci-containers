// Copyright  2019 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"bytes"
	kubecontext "context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"net"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
)

const (
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorRed    = "\033[31m"
	ColorPurple = "\033[35m"
	ColorReset  = "\033[0m"
	// Add more colors if needed
)

const (
	LastTableNumBrAccess = 9
	LastTableNumBrInt    = 15
)

// Struct to hold packet summary
type PacketSummary struct {
	InPort        string
	OutPort       string
	TunnelID      string
	PacketDropped bool
	previousTable int
	tcp_dst       string
	ip_dst        string
	snat_ip       string
	ct_mark       string
}

var nodeIdMaps *NodeIdMaps
var tcpFlag bool
var tcpSrc int
var tcpDst int
var verbose bool
var gbp bool
var username string
var apicpassword string
var leafpassword string
var policy bool
var endpoint bool
var apic string
var ct_mark string

type Bridge struct {
	br_type       string
	brFlows       string
	brFlowEntries map[int][]string
	out_br_buff   string
	nodename      string
	summary       *PacketSummary
	ovsPod        string
	opflexPod     string
}

//* in_port=<port-number>: Specifies the input port.
//* dl_src=<MAC-address>: Specifies the Ethernet source address.
//* dl_dst=<MAC-address>: Specifies the Ethernet destination address.
//* dl_type=<ethertype>: Specifies the Ethernet type (e.g., 0x0800 for IP).
//* nw_src=<IP-address>: Specifies the IP source address.
//* nw_dst=<IP-address>: Specifies the IP destination address.
//* nw_proto=<protocol-number>: Specifies the IP protocol (e.g., 6 for TCP, 17 for UDP).
//* tp_src=<port-number>: Specifies the TCP/UDP source port.
//* tp_dst=<port-number>: Specifies the TCP/UDP destination port.

type EndPoints struct {
	Uuid              string `json:"uuid"`
	EgPolicySpace     string `json:"eg-policy-space"`
	EndpointGroupName string `json:"endpoint-group-name"`
	QosPolicy         struct {
	} `json:"qos-policy"`
	Ip                    []string `json:"ip"`
	Mac                   string   `json:"mac"`
	AccessInterface       string   `json:"access-interface"`
	AccessUplinkInterface string   `json:"access-uplink-interface"`
	InterfaceName         string   `json:"interface-name"`
	Attributes            struct {
		InterfaceName string `json:"interface-name"`
		Namespace     string `json:"namespace"`
		VmName        string `json:"vm-name"`
	} `json:"attributes"`
}

type Service struct {
	Uuid              string `json:"uuid"`
	DomainPolicySpace string `json:"domain-policy-space"`
	DomainName        string `json:"domain-name"`
	ServiceMode       string `json:"service-mode"`
	ServiceType       string `json:"service-type"`
	ServiceMapping    []struct {
		ServiceIp        string   `json:"service-ip"`
		ServiceProto     string   `json:"service-proto"`
		ServicePort      int      `json:"service-port"`
		NextHopIps       []string `json:"next-hop-ips"`
		NextHopPort      int      `json:"next-hop-port"`
		ConntrackEnabled bool     `json:"conntrack-enabled"`
		NodePort         int      `json:"node-port"`
		SessionAffinity  struct {
			ClientIp struct {
				TimeoutSeconds int `json:"timeout-seconds"`
			} `json:"client-ip"`
		} `json:"session-affinity"`
	} `json:"service-mapping"`
	Attributes struct {
		Name        string `json:"name"`
		Namespace   string `json:"namespace"`
		ServiceName string `json:"service-name"`
	} `json:"attributes"`
}

type GBPObject struct {
	Subject        string     `json:"subject"`
	URI            string     `json:"uri"`
	Properties     []Property `json:"properties"`
	Children       []string   `json:"children"`
	ParentSubject  string     `json:"parent_subject"`
	ParentURI      string     `json:"parent_uri"`
	ParentRelation string     `json:"parent_relation"`
}

type Property struct {
	Name string      `json:"name"`
	Data interface{} `json:"data"`
}

type Reference struct {
	Subject      string `json:"subject"`
	ReferenceURI string `json:"reference_uri"`
}

var BrAccessRegisterMap = map[string]string{
	"NXM_NX_REG0": "SecGrpId",
	"NXM_NX_REG5": "VlanId",
	"NXM_NX_REG6": "ConnTrackZoneId",
	"NXM_NX_REG7": "OutputPort",
}

var BrRegToNXMMap = map[string]string{
	"reg0":  "NXM_NX_REG0",
	"reg1":  "NXM_NX_REG1",
	"reg2":  "NXM_NX_REG2",
	"reg3":  "NXM_NX_REG3",
	"reg4":  "NXM_NX_REG4",
	"reg5":  "NXM_NX_REG5",
	"reg6":  "NXM_NX_REG6",
	"reg7":  "NXM_NX_REG7",
	"reg8":  "NXM_NX_REG8",
	"reg9":  "NXM_NX_REG9",
	"reg10": "NXM_NX_REG10",
	"reg11": "NXM_NX_REG11",
	"reg12": "NXM_NX_REG12",
}

//var idMapFiles = map[string]string{
//	"secGroupSet":       "/usr/local/var/lib/opflex-agent-ovs/ids/secGroupSet.id",
//	"service":           "/usr/local/var/lib/opflex-agent-ovs/ids/service.id",
//	"floodDomain":       "/usr/local/var/lib/opflex-agent-ovs/ids/floodDomain.id",
//	"routingDomain":     "/usr/local/var/lib/opflex-agent-ovs/ids/routingDomain.id",
//	"conntrack":         "/usr/local/var/lib/opflex-agent-ovs/ids/conntrack.id",
//	"bridgeDomain":      "/usr/local/var/lib/opflex-agent-ovs/ids/bridgeDomain.id",
//	"externalNetwork":   "/usr/local/var/lib/opflex-agent-ovs/ids/externalNetwork.id",
//	"l24classifierRule": "/usr/local/var/lib/opflex-agent-ovs/ids/l24classifierRule.id",
//}

var BrAccessFileRegisterMap = map[string]string{
	"NXM_NX_REG0": "secGroupSet",
	//	"NXM_NX_REG5": "VlanId",
	"NXM_NX_REG6": "conntrack",
	//	"NXM_NX_REG7": "OutputPort",
}
var BrIntFilesRegisterMap = map[string]string{
	//"NXM_NX_REG0":  "sEPG",
	//"NXM_NX_REG2":  "dEPG",
	"NXM_NX_REG4": "bridgeDomain",
	"NXM_NX_REG5": "floodDomain",
	"NXM_NX_REG6": "routingDomain",
	//"NXM_NX_REG7":  "OutputPort",
	"NXM_NX_REG8": "service",
	//"NXM_NX_REG9":  "ipv6ServiceAddr",
	//"NXM_NX_REG10": "ipv6ServiceAddr",
	//"NXM_NX_REG11": "ipv6ServiceAddr",
	//"NXM_NX_REG12": "ctMark",
}

var BrIntRegisterMap = map[string]string{
	"NXM_NX_REG0":  "Source EPG",
	"NXM_NX_REG2":  "Destination EPG",
	"NXM_NX_REG4":  "BridgeDomain Id",
	"NXM_NX_REG5":  "FloodDomain Id",
	"NXM_NX_REG6":  "RoutingDomain Id",
	"NXM_NX_REG7":  "OutputPort",
	"NXM_NX_REG8":  "serviceAddr",
	"NXM_NX_REG9":  "ipv6ServiceAddr",
	"NXM_NX_REG10": "ipv6ServiceAddr",
	"NXM_NX_REG11": "ipv6ServiceAddr",
	"NXM_NX_REG12": "ctMark",
}

var BrAccessMetadataMap = map[string]string{
	"0x1":   "POP_VLAN: Pop the VLAN tag",
	"0x2":   "PUSH_VLAN: Push the VLAN tag stored in REG5",
	"0x200": "EGRESS_DIR: Indicates that packet direction is egress",
	"0x800": "DROP_LOG: Indicates that if this packet is dropped, then it should be logged",
}

var BrIntMetadataMap = map[string]string{
	"0x100": "POLICY_APPLIED: Indicates that policy has been applied already for this flow",
	"0x200": "FROM_SERVICE_INTERFACE: Indicates that a flow comes from a service interface",
	"0x400": "ROUTED: Indicates that a packet has been routed and is allowed to hairpin",
	"0x800": "DROP_LOG: Indicates that if this packet is dropped, then it should be logged",
	"0x1":   "RESUBMIT_DST: Indicates resubmit to the first dest table with the source registers set to the corresponding values for the EPG in REG7",
	"0x2":   "NAT: Indicates perform outbound NAT action and then resubmit with the source EPG set to the mapped NAT EPG",
	"0x3":   "REV_NAT: Indicates Output to the interface in REG7, but intercept ICMP error replies and overwrite the encapsulated error packet's source address with the (rewritten) destination address of the outer packet",
	"0x4":   "TUNNEL: Indicates output to the tunnel destination appropriate for the EPG",
	"0x5":   "FLOOD: Indicates output to the flood group appropriate for the EPG",
	"0x7":   "REMOTE_TUNNEL: Indicates output to the tunnel destination specified in the output register",
	"0x8":   "HOST_ACCESS: Indicates output to the veth_host_ac destination specified in output register",
}

// Br-Access Table descriptions with IDs
var brAccessTableDescriptions = map[int]string{
	0:  "DROP_LOG_TABLE (Handles drop log policy)",
	1:  "SERVICE_BYPASS_TABLE (Bypass loopback flows from service backends to service from security group checks)",
	2:  "SECURITY_GROUP_MAP_TABLE (Map packets to a security group and set their destination port after applying policy)",
	3:  "SYS_SEC_GRP_IN_TABLE (Enforce system security group policy on packets coming into the endpoint from switch)",
	4:  "SEC_GROUP_IN_TABLE (Enforce security group policy on packets coming into the endpoint from the switch)",
	5:  "SYS_SEC_GRP_OUT_TABLE (Enforce system security group policy on packets coming out of the endpoints to the switch)",
	6:  "SEC_GROUP_OUT_TABLE (Enforce security group policy on packets coming out from the endpoint to the switch)",
	7:  "TAP_TABLE (Punt packets to the controller/other ports to examine and handle additional policy: currently DNS packets)",
	8:  "OUT_TABLE (Output to the final destination port)",
	9:  "EXP_DROP_TABLE (Handle explicitly dropped packets here based on the drop-log config)",
	10: "NUM_FLOW_TABLES (The total number of flow tables)",
}

var brIntTableDescriptions = map[int]string{
	0:  "DROP_LOGS (Handles drop log policy)",
	1:  "SEC_TABLE (Handles port security/ingress policy)",
	2:  "SRC_TABLE (Maps source addresses to endpoint groups and sets this mapping into registers for use by later tables)",
	3:  "SNAT_REV_TABLE (External World to SNAT IP: UN-SNAT traffic using connection tracking. Changes network destination using state in connection tracker and forwards traffic to the endpoint.)",
	4:  "SERVICE_REV_TABLE (For traffic returning from load-balanced service IP addresses, restore the source address to the service address)",
	5:  "BRIDGE_TABLE (\nFor flows that can be forwarded through bridging, it maps the destination L2 address to an endpoint group and the next hop interface, then stores this mapping in registers for use by subsequent tables. It also manages replies for protocols handled by the agent or switch, such as ARP and NDP)",
	6:  "SERVICE_NEXTHOP_TABLE (For load-balanced service IPs, map from a bucket ID to the appropriate destination IP address.)",
	7:  "ROUTE_TABLE (For flows that require routing, maps the destination L3 address to an endpoint group or external network and next hop action and sets this information into registers for use by later tables.)",
	8:  "SNAT_TABLE (Endpoint -> External World: Traffic that needs SNAT is determined after routing local traffic. SNAT changes the source IP address and source port based on configuration in the endpoint file.)",
	9:  "NAT_IN_TABLE (For flows destined for a NAT IP address, determine the source external network for the mapped IP address and set this in the source registers to allow applying policy to NATed flows.)",
	10: "LEARN_TABLE (Source for flows installed by OVS learn action)",
	11: "SERVICE_DST_TABLE (Map traffic returning from a service interface to the appropriate endpoint interface.)",
	12: "POL_TABLE (Allow policy for the flow based on the source and destination groups and the contracts that are configured.)",
	13: "STATS_TABLE (Flow stats computation)",
	14: "OUT_TABLE (Apply a destination action based on the action set in the metadata field.)",
	15: "EXP_DROP_TABLE (Handle explicitly dropped packets here based on the drop-log config)",
	16: "NUM_FLOW_TABLES (The total number of flow tables)",
}

var idMapFiles = map[string]string{
	"secGroupSet":       "/usr/local/var/lib/opflex-agent-ovs/ids/secGroupSet.id",
	"service":           "/usr/local/var/lib/opflex-agent-ovs/ids/service.id",
	"floodDomain":       "/usr/local/var/lib/opflex-agent-ovs/ids/floodDomain.id",
	"routingDomain":     "/usr/local/var/lib/opflex-agent-ovs/ids/routingDomain.id",
	"conntrack":         "/usr/local/var/lib/opflex-agent-ovs/ids/conntrack.id",
	"bridgeDomain":      "/usr/local/var/lib/opflex-agent-ovs/ids/bridgeDomain.id",
	"externalNetwork":   "/usr/local/var/lib/opflex-agent-ovs/ids/externalNetwork.id",
	"l24classifierRule": "/usr/local/var/lib/opflex-agent-ovs/ids/l24classifierRule.id",
}

var script = `
import deepdiff
from deepdiff.helper import CannotCompare
import json
import argparse
from argparse import RawTextHelpFormatter
import getpass
import requests
import subprocess
import paramiko
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

desc="""

python diff.py -leaf1 1.1.1.1 -leaf2 2.2.2.2 -user admin -policy True -endpoint True -validation True

policy is a string if given True it processes policyCache files
endpoint is a string if given True it processes EpInventoryCache files
By default, both parameters are set to False
"""

dumpPolicyCacheCmd = "icurl -k -X POST 'https://localhost/api/opflexp/debug/dumpGenieCache.xml'"
dumpEpInventoryCacheCmd = "icurl -k -X POST 'https://localhost/api/opflexp/debug/dumpRemoteEpCache.xml'"
policyCachePath = "/var/log/dme/log/dme_logs/GenieCache.json"
epInventoryCachePath = "/var/log/dme/log/dme_logs/GenieEpInventoryCache.json"

class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, deepdiff.model.PrettyOrderedSet):
            return list(obj)
        else:
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

def compare_func(x, y, level=None):
    try:
        return x['domain'] == y['domain'] and x['name'] == y['name']
    except Exception:
        raise CannotCompare() from None

def isPolicy(entry):
    if 'subject' in entry and 'uri' in entry:
        return True
    else:
        return False

def isPolicyWithDomain(entry):
    if all(p in entry for p in ["domain","name", "objectandchildren"]):
        if not isPolicy(entry["objectandchildren"]):
            return False
        return True

def isAgent(entry):
    if "agent_ip" in entry and "agent_identity" in entry:
        return True
    else:
        return False
    
def isAgentWithDomain(entry):
    if all(p in entry for p in ["nwIfId","domain", "agents L2/L3 EP caching"]):
        for agent in entry["agents L2/L3 EP caching"]:
            if not isAgent(agent):
                return False
        return True

def isEndpoint(entry):
    if 'uuid' in entry:
        return True
    else:
        return False

def isGenieObjOfEndpoint(entry):
    if 'subject' in entry and 'uri' in entry:
        return True
    else:
        return False

def isProperty(entry):
    if 'name' in entry and 'data' in entry:
        return True
    else:
        return False

def scpCommandonSSH(ip_address, username, password, sourcePath, destinationPath):
    ssh_client = paramiko.SSHClient()

    # Connect to the remote machine.
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(ip_address, username=username, password=password)
    # scpConn = SCPClient(ssh_client.get_transport())
    scpConn = ssh_client.open_sftp()
    scpConn.get(sourcePath, destinationPath)

    scpConn.close()
    ssh_client.close()
    
    return None

def postDumpAPI(mgmt_ip, username, password, dumpCacheName):
    #leaf1 = "https://" + mgmt_ip
    #leaf = Node(leaf1)
    #try:
    #    leaf.methods.Login(username, password).POST()
    #except:
    #    print("Exception occured while trying to login " + mgmt_ip)
        
    s = requests.Session()

    data = f"<aaaUser name=\"{username}\" pwd=\"{password}\"/>"
    url_login = f"https://{mgmt_ip}/api/aaaLogin.xml"
    resp = s.post(url_login, data, verify=False, timeout=300)
    assert resp.status_code == 200, "Error in posting login request"
    url_dump_ep_cache = f"https://{mgmt_ip}/api/opflexp/debug/dump{dumpCacheName}.xml"
    resp = s.post(url_dump_ep_cache, verify=False, timeout=300)
    assert resp.status_code == 200, "Error in posting dump request"

def dumpAndDownloadCache(mgmt_ip, username, password, cacheType, downloadCachePath):
    # Dump Cache to leaf
    if cacheType == 'policy':
        postDumpAPI(mgmt_ip, username, password, 'GenieCache')
    elif cacheType == 'endpoint':
        postDumpAPI(mgmt_ip, username, password, 'RemoteEpCache')
        
    # Download Cache
    if cacheType == 'policy':
        scpCommandonSSH(mgmt_ip, username, password, policyCachePath, downloadCachePath)
    elif cacheType == 'endpoint':
        scpCommandonSSH(mgmt_ip, username, password, epInventoryCachePath, downloadCachePath)
        
def collectTechsupport(mgmt_ip, username, password):
    print("Collecting tech support for ", mgmt_ip)
    ssh_client = paramiko.SSHClient()

    # Connect to the remote machine.
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(mgmt_ip, username=username, password=password)
    stdin, stdout, error = ssh_client.exec_command("techsupport local", get_pty=True)
    for line in iter(stdout.readline, ''):
        output = line
        print(output, end='')
    ssh_client.close()

    return output

def getRepeatedElements(input_list):
    repeated_elementsWithCount = [(x, input_list.count(x)) for i,x in enumerate(input_list) if input_list.count(x) > 1]
    return list(set(repeated_elementsWithCount))

def getMACAndIpOfEndpoint(endpoint):
    mac, ip = None, None
    for genie_obj in endpoint['genie_objects']:
        if 'subject' not in genie_obj:
            # This genie object only has ip but no mac address
            mac,ip = None, genie_obj['ip']
        else:
            if genie_obj['subject'] == 'InvRemoteInventoryEp':
                for prop in genie_obj['properties']:
                    if prop['name'] == 'mac':
                        mac = prop['data']
                if mac is None:
                    print("MAC property not found in InvRemoteInventoryEp GenieObject", genie_obj['uri'])
            elif genie_obj['subject'] == 'InvRemoteIp':
                for prop in genie_obj['properties']:
                    if prop['name'] == 'ip':
                        ip = prop['data']
                if ip is None:
                    print("Ip property not found in InvRemoteIp GenieObject", genie_obj['uri'])
    return mac, ip

def getAgentInfo(agent):
    if 'agent_ip' in agent and 'agent_identity' in agent :
        return agent['agent_ip'], agent['agent_identity']

def getPropertyInfo(property):
    if isinstance(property['data'], dict):
        # Type-2 property - Property for Relation source of main policy
        return property['name'], property['data']['subject'], property['data']['reference_uri']
    else:
        # Type-1 property - Regular property for main policy
        return property['name'], property['data']
        
def outputPolicyCacheDiff(cache_name, entries, policycache):
    if cache_name == 'cache1':
        attribute = 't1'
    elif cache_name == 'cache2':
        attribute = 't2'
    else:
        print(f"Invalid argument 'cache_name' - {cache_name} - can only be 'cache1' or 'cache2'")
        exit()
    
    for entry in entries[cache_name]:
        if isPolicyWithDomain(getattr(entry, attribute)):
            # Check for addition/deletion of policy
            policycache[cache_name]['policy'].append(getattr(entry, attribute)['name'])
        elif isPolicy(getattr(entry, attribute)):
            # Check for addition/deletion of child of policy
            policycache[cache_name]['policy'].append(getattr(entry, attribute)['uri'])
        elif isProperty(getattr(entry, attribute)):
            # Check for addition/deletion of property and get policy uri
            policycache[cache_name]['property'].append([getPropertyInfo(getattr(entry, attribute)), getattr(entry.up.up,attribute)['uri']])
        # else:
        #     print("This object is of unknkown type, hence not handling this case")
            
    if policycache[cache_name]['policy']:    
        print('\t\tPolicies')
        for policy in policycache[cache_name]['policy']:
            print('\t\t\t'+policy)
            
    if policycache[cache_name]['property']:
        print('\t\tProperty')
        for property in policycache[cache_name]['property']:
            print('\t\t\t', property, sep='')

def outputPolicyCacheModify(entries_valuediff, policycache):
    # Assume that only 'data' in property can be modified
    for entry in entries_valuediff:
        pathInfo = entry.path(output_format='list')[-2:]
        if pathInfo[1] == 'reference_uri' and pathInfo[0] == 'data':
            # Type-2 Property - Property for Relation source of child policy
            p1, p2 = getPropertyInfo(entry.up.up.t1), getPropertyInfo(entry.up.up.t2)
            sp1, sp2 = entry.up.up.up.up.t1['uri'], entry.up.up.up.up.t2['uri']
            if p1[0] == p2[0] and p1[1] == p2[1] and sp1 == sp2:
                policycache['modify'].append([p1[0], p1[1], f"cache1 : {p1[-1]}", f"cache2 : {p2[-1]}", f"URI : {entry.up.up.up.up.t1['uri']}"])
        elif pathInfo[1] == 'data':
            # Type-1 property - Regular property for main policy
            p1, p2 = getPropertyInfo(entry.up.t1), getPropertyInfo(entry.up.t2)
            sp1, sp2 = entry.up.up.up.t1['uri'], entry.up.up.up.t2['uri']
            # Comparing sp1 and sp2 as to verify this modification is related to the same policy URI else ignore, this is needed due to a bug in DeefDiff
            if p1[0] == p2[0] and sp1 == sp2:
                policycache['modify'].append([p1[0], f"cache1 : {p1[-1]}", f"cache2 : {p2[-1]}", f"URI : {entry.up.up.up.t1['uri']}"])
        # else:
        #     print(f"Object identified for modification {pathInfo[1]} is not a property or unknown type. This is not handled")
    
    for mod in policycache['modify']:
        for e in mod:
            print('\t\t', e, sep='')
        print()
        
def outputEpCacheDiff(cache_name, entries, epcache):
    if cache_name == 'cache1':
        attribute = 't1'
    elif cache_name == 'cache2':
        attribute = 't2'
    else:
        print(f"Invalid argument 'cache_name' - {cache_name} - can only be 'cache1' or 'cache2'")
        exit()
        
    for entry in entries[cache_name]:
        if isAgentWithDomain(getattr(entry, attribute)):
            # Check for addition/deletion of agent with domain
            for agent in getattr(entry, attribute)['agents L2/L3 EP caching']:
                epcache[cache_name]['Agent'].append([*getAgentInfo(agent), getattr(entry, attribute)['nwIfId'], getattr(entry, attribute)['domain']])
        elif isAgent(getattr(entry, attribute)):
            # Check for addition/deletion of agent
            epcache[cache_name]['Agent'].append([*getAgentInfo(getattr(entry, attribute)), getattr(entry.up.up, attribute)['nwIfId'], getattr(entry.up.up, attribute)['domain']])
        elif isEndpoint(getattr(entry, attribute)):
            # Check for addition/deletion of endpoint
            epcache[cache_name]['Endpoint'].append([getattr(entry, attribute)['uuid'], getAgentInfo(getattr(entry.up.up, attribute))])
        elif isGenieObjOfEndpoint(getattr(entry, attribute)):
            # Check for addition/deletion of GenieObject of endpoint
            epcache[cache_name]['GenieObject of Endpoint'].append([getattr(entry, attribute)['uri'], getattr(entry.up.up, attribute)['uuid']])
        elif isProperty(getattr(entry, attribute)):
            # Check for addition/deletion of property of GenieObject of endpoint
            epcache[cache_name]['Property of Endpoint GenieObject'].append([getPropertyInfo(getattr(entry, attribute)), getattr(entry.up.up, attribute)['uri'], getattr(entry.up.up.up.up, attribute)['uuid']])
        # else:
        #     print("This object is of unknkown type, hence not handling this case")
    
    for key in epcache[cache_name]:
        if epcache[cache_name][key]:    
            print('\t\t',key, sep='')
            for agent in epcache[cache_name][key]:
                for e in agent:
                    print('\t\t\t',e, sep='')
                print()

def outputEpCacheModify(entries_valuediff, epcache):
    for entry in entries_valuediff:
        pathInfo = entry.path(output_format='list')[-2:]
        if pathInfo[-1] == 'agent_ip' or pathInfo[-1] == 'agent_identity':
            # Modifcation in agent property
            epcache['modify']['Agent Property'].append([pathInfo[-1], f"cache1 : {entry.t1}", f"cache2 : {entry.t2}", f"Domain : {(entry.up.up.up.t1['nwIfId'], entry.up.up.up.t1['domain'])}"])
        elif pathInfo[-1] == 'uuid':
            # Modification of endpoint
            epcache['modify']['Endpoint Property'].append([pathInfo[-1], f"cache1 : {entry.t1}", f"cache2 : {entry.t2}", f"Agent : {getAgentInfo(entry.up.up.up.t1)}"])
        elif pathInfo[1] == 'reference_uri' and pathInfo[0] == 'data':
            # Type-2 Property - Property for Relation source of child policy
            p1, p2 = getPropertyInfo(entry.up.up.t1), getPropertyInfo(entry.up.up.t2)
            sp1, sp2 = entry.up.up.up.up.t1['uri'], entry.up.up.up.up.t2['uri']
            # Comparing sp1 and sp2 as to verify this modification is related to the same endpoint URI else ignore, this is needed due to a bug in DeefDiff
            if p1[0] == p2[0] and p1[1] == p2[1] and sp1 == sp2:
                epcache['modify']['Property of Endpoint GenieObject'].append([p1[0], p1[1], f"cache1 : {p1[-1]}", f"cache2 : {p2[-1]}", f"URI : {entry.up.up.up.up.t1['uri']}", f"UUID : {entry.up.up.up.up.up.up.t1['uuid']}"])
        elif pathInfo[1] == 'data':
            # Type-1 property - Regular property for main policy
            p1, p2 = getPropertyInfo(entry.up.t1), getPropertyInfo(entry.up.t2)
            sp1, sp2 = entry.up.up.up.t1['uri'], entry.up.up.up.t2['uri']
            if p1[0] == p2[0] and sp1 == sp2:
                epcache['modify']['Property of Endpoint GenieObject'].append([p1[0], f"cache1 : {p1[-1]}", f"cache2 : {p2[-1]}", f"URI : {entry.up.up.up.t1['uri']}", f"UUID : {entry.up.up.up.up.up.t1['uuid']}"])
        # else:
        #     print(f"Object identified for modification {pathInfo[1]} is not a property or unknown type. This is not handled")

            
    for key in epcache['modify']:
        if epcache['modify'][key]:    
            print('\t\t',key, sep='')
            for entry in epcache['modify'][key]:
                for e in entry:
                    print('\t\t\t',e, sep='')
                print()

def validateEpCache(ep_cache):
    error_dict = {}
    if 'Genie RemoteEpInventory cache entries' not in ep_cache:
        return
    for agentDomain in ep_cache['Genie RemoteEpInventory cache entries']:
        # Check if all agents in a domain have unique Ip and name
        agentIp_list = list(agent['agent_ip'] for agent in agentDomain['agents L2/L3 EP caching'])
        agentIdentity_list = list(agent['agent_identity'] for agent in agentDomain['agents L2/L3 EP caching'])
        repeatedAgentIp = getRepeatedElements(agentIp_list)
        repeatedAgentName = getRepeatedElements(agentIdentity_list)
        if repeatedAgentIp or repeatedAgentName:
            key = (agentDomain['nwIfId'], agentDomain['domain'])
            error_dict[key] = {}
            if repeatedAgentIp:
                error_dict[key]['repeatedAgentIp'] = repeatedAgentIp
            if repeatedAgentName:
                error_dict[key]['repeatedAgentName'] = repeatedAgentName
        else:
            repeatedEndpoints = {}
            for agent in agentDomain['agents L2/L3 EP caching']:
                endpointsWithUniqueUUID = {}
                agentInfo = (agent['agent_ip'], agent['agent_identity'])
                for endpoint in agent['endpoints']:
                    # Check if all endpoints across all agents in a domain have unique UUID
                    if endpoint['uuid'] not in endpointsWithUniqueUUID:
                        endpointsWithUniqueUUID[endpoint['uuid']] = []
                        endpointsWithUniqueUUID[endpoint['uuid']].append(agentInfo)
                    else:
                        if endpoint['uuid'] not in repeatedEndpoints:
                            repeatedEndpoints[endpoint['uuid']] = []
                            repeatedEndpoints[endpoint['uuid']].extend(endpointsWithUniqueUUID[endpoint['uuid']])
                        if agentInfo not in repeatedEndpoints[endpoint['uuid']]:
                            # If endpoint is already present in repeatedEndpoints but not for this agent entry so its first repeated endpoint in this agent
                            repeatedEndpoints[endpoint['uuid']].extend(endpointsWithUniqueUUID[endpoint['uuid']])
                        repeatedEndpoints[endpoint['uuid']].append(agentInfo)
            if repeatedEndpoints:
                key = (agentDomain['nwIfId'], agentDomain['domain'])
                error_dict[key] = {}
                error_dict[key]['repeatedEndpoints'] = repeatedEndpoints
            else:
                # If there are no duplicate endpoints with the same UUID, then validate MAC and IP addresses of endpoints
                repeatedAddresses = {'mac': {}, 'ip': {}, 'emptyMAC': {}}
                for agent in agentDomain['agents L2/L3 EP caching']:
                    endpointWithUniqueMAC, endpointWithUniqueIP, endpointEmptyMAC = {}, {}, {}
                    agentInfo = (agent['agent_ip'], agent['agent_identity'])
                    for endpoint in agent['endpoints']:
                        # Check if all endpoints across all agents in a domain have unique MAC / IP(if present)
                        mac, ip = getMACAndIpOfEndpoint(endpoint)
                        if mac is None:
                            if endpoint['uuid'] not in repeatedAddresses['emptyMAC']:
                                repeatedAddresses['emptyMAC'] = []
                            repeatedAddresses['emptyMAC'].append([endpoint['uuid'], agentInfo])
                        # if mac is not None:
                        #     # Check for any repeated mac from mac list
                        #     if mac not in endpointWithUniqueMAC:
                        #         endpointWithUniqueMAC[mac] = []
                        #         endpointWithUniqueMAC[mac].append([endpoint['uuid'], agentInfo])
                        #     else:
                        #         if mac not in repeatedAddresses['mac']:
                        #             repeatedAddresses['mac'][mac] = []
                        #         if agentInfo not in repeatedAddresses['mac'][mac]:
                        #             repeatedAddresses['mac'][mac].append([endpoint['uuid'], agentInfo])
                        #         repeatedAddresses['mac'][mac].append([endpoint['uuid'], agentInfo])
                        if ip is not None:
                            # Check for any repeated Ip from the ip list
                            if ip not in endpointWithUniqueIP:
                                endpointWithUniqueIP[ip] = []
                                endpointWithUniqueIP[ip].append([endpoint['uuid'], agentInfo])
                            else:
                                if ip not in repeatedAddresses['ip']:
                                    repeatedAddresses['ip'][ip] = []
                                    repeatedAddresses['ip'][ip].extend(endpointWithUniqueIP[ip])
                                if endpointWithUniqueIP[ip][0] not in repeatedAddresses['ip'][ip]:
                                    repeatedAddresses['ip'][ip].extend(endpointWithUniqueIP[ip])
                                repeatedAddresses['ip'][ip].append([endpoint['uuid'], agentInfo])
                
                if repeatedAddresses['ip']:
                    key = (agentDomain['nwIfId'], agentDomain['domain'])
                    error_dict[key] = {}
                    error_dict[key]['repeatedAddresses'] = repeatedAddresses
    return error_dict  

                        
def outputErrorsEpCache(error_dict):
    for infAndDomain in error_dict:
        print(f"\t\t\tErrors in agents with domain (nwIfId, domain) - ({infAndDomain[0]}, {infAndDomain[1]})")             
        if 'repeatedAgentIp' in error_dict[infAndDomain]:
            print("\t\t\t\tMultiple Agents having same Ip - ")
            for agentIp in error_dict[infAndDomain]['repeatedAgentIp']:
                print('\t\t\t\t\t',f"{agentIp[1]} Agents with ",agentIp[0], sep='')
        if 'repeatedAgentName' in error_dict[infAndDomain]:
            print("\t\t\t\tMultiple Agents having same Name - ")
            for agentName in error_dict[infAndDomain]['repeatedAgentName']:
                print('\t\t\t\t\t',f"{agentName[1]} Agents with ",agentName[0], sep='')
        if 'repeatedEndpoints' in error_dict[infAndDomain]:
            agents = [len(getRepeatedElements(error_dict[infAndDomain]['repeatedEndpoints'][endpoint])) != 0 for endpoint in error_dict[infAndDomain]['repeatedEndpoints']]
            if any(agents):
                print("\t\t\t\tFollowing endpoints are repeated in agents - ")
                for endpoint in error_dict[infAndDomain]['repeatedEndpoints']:
                    agents = getRepeatedElements(error_dict[infAndDomain]['repeatedEndpoints'][endpoint])
                    for agent in agents:
                        print('\t\t\t\t\t', f"{agent[1]} endpoints with UUID - ", endpoint, '\tAgent - ', agent[0], sep='')
        if 'repeatedAddresses' in error_dict[infAndDomain]:
            # if error_dict[infAndDomain]['repeatedAddresses']['mac']:
            #    print("\t\t\t\tFollowing are MAC addresses present in multiple endpoints -")
            #    for mac in error_dict[infAndDomain]['repeatedAddresses']['mac']:
            #        print('\t\t\t\t\t', mac, '\tEndpoint - ', error_dict[infAndDomain]['repeatedAddresses']['mac'][mac], sep='')
            if error_dict[infAndDomain]['repeatedAddresses']['ip']:
                print("\t\t\t\tFollowing are Ip addresses present in multiple endpoints -")
                for ip in error_dict[infAndDomain]['repeatedAddresses']['ip']:
                    # print('\t\t\t\t\t', ip, '\tEndpoint - ', error_dict[infAndDomain]['repeatedAddresses']['ip'][ip], sep='')
                    print('\t\t\t\t\t', ip, sep='')
                    print('\t\t\t\t\t', "Endpoints -", sep='')
                    for entry in error_dict[infAndDomain]['repeatedAddresses']['ip'][ip]:
                        print('\t\t\t\t\t', entry)
                    print()
            
def compareCache(cache1_path, cache2_path, comparePolicy):
    with open(cache1_path) as f1, open(cache2_path) as f2:
        data1 = json.load(f1)
        data2 = json.load(f2)

    diff = deepdiff.DeepDiff(data1, data2, ignore_order=True, get_deep_distance=True, cutoff_distance_for_pairs=0.3, cutoff_intersection_for_pairs=0.7, cache_size=5000, iterable_compare_func=compare_func)
    diff_tree = deepdiff.DeepDiff(data1, data2, ignore_order=True, view="tree", cutoff_distance_for_pairs=0.3, cutoff_intersection_for_pairs=0.7, cache_size=5000, iterable_compare_func=compare_func).to_dict()
    k = diff.to_dict()

    with open ('difference.json','w') as f:
        json.dump(k, f, indent= 4, cls=SetEncoder)

    entries = {'cache1': [], 'cache2':[]}    
    entries_valuediff = []

    # dictionary_item_added - Only present in cache 2
    if 'dictionary_item_added' in diff_tree:
        for entry in diff_tree['dictionary_item_added']:
            entries['cache2'].append(entry.up)

    # dictionary_item_removed - Only present in cache 1
    if 'dictionary_item_removed' in diff_tree:
        for entry in diff_tree['dictionary_item_removed']:
            entries['cache1'].append(entry.up)
        
    # values_changed - Values changed in cache 2
    if 'values_changed' in diff_tree:
        for entry in diff_tree['values_changed']:
            entries_valuediff.append(entry)

    # iterable_item_removed - Only present in cache 1 [list]
    if 'iterable_item_removed' in diff_tree:
        for entry in diff_tree['iterable_item_removed']:
            entries['cache1'].append(entry)

    # iterable_item_added - Only present in cache 2 [list]
    if 'iterable_item_added' in diff_tree:
        for entry in diff_tree['iterable_item_added']:
            entries['cache2'].append(entry)

    if comparePolicy:
        if not diff_tree:
            print(f"No Inconsistencies found between the policy caches in leafs, caches are copied here: \nCache1 {cache1_path}\nCache2 {cache2_path}\n")
            return
            
        print('Policy Cache')
        print('----------------------------------------------------------------')
        policycache = {'cache1': {}, 'cache2': {}, 'modify': []}
        policycache1, policycache2 = [
            {key: [] for key in ['policy', 'property']}
            for _ in range(2)
            ]
        policycache['cache1'] = policycache1
        policycache['cache2'] = policycache2
        print("\tPolicies present in only leaf1's cache:")
        outputPolicyCacheDiff('cache1', entries, policycache)
        
        print("\n\tPolicies present in only leaf2's cache:")        
        outputPolicyCacheDiff('cache2', entries, policycache)
        
        print("\n\tModifications:")
        outputPolicyCacheModify(entries_valuediff, policycache)
        print('----------------------------------------------------------------\n')
    else:
        print('EpInventory Cache')
        print('----------------------------------------------------------------')
        epcache = {'cache1': {}, 'cache2': {}, 'modify': {}}
        epcache1, epcache2 = [
            {key: [] for key in ['Agent', 'Endpoint', 'GenieObject of Endpoint', 'Property of Endpoint GenieObject']}
            for _ in range(2)
            ]
        epcache['cache1'] = epcache1
        epcache['cache2'] = epcache2
        epcache['modify'] = {key: [] for key in ['Agent Property', 'Endpoint Property', 'Property of Endpoint GenieObject']}
        
        if isValidationRequired:
            cache1_errors = validateEpCache(data1)
            cache2_errors = validateEpCache(data2)
            if cache1_errors or cache2_errors:
                print("\tErrors")
                if cache1_errors:
                    print("\t\t Errors found in Cache 1:")
                    outputErrorsEpCache(cache1_errors)
                if cache2_errors:
                    print("\t\t Errors found in Cache 2:")
                    outputErrorsEpCache(cache2_errors)
                # print("\t\t Exiting due to above errors")
            else:
                print("No Errors found in both the ep cache individually!\n")
        
        if not diff_tree:
            print(f"No Inconsistencies found between the Ep caches in leafs, caches are copied here: \nCache1 {cache1_path}\nCache2 {cache2_path}\n")
            return
        
        print("\n\tInconsistencies found -\n")  
        print("\tPresent Only in Cache 1:")
        outputEpCacheDiff('cache1', entries, epcache)
        
        print("\n\tPresent Only in Cache 2:")
        outputEpCacheDiff('cache2', entries, epcache)
        
        print("\n\tModifications:")
        outputEpCacheModify(entries_valuediff, epcache)
        
        print('----------------------------------------------------------------\n')
    
    if diff_tree:
        return True
    else:
        return False

def parse_args():
    parser = argparse.ArgumentParser(description=desc, formatter_class=RawTextHelpFormatter)
    parser.add_argument("-leaf1", "--leaf1", type=str, required=True)
    parser.add_argument("-leaf2", "--leaf2", type=str, required=True)
    parser.add_argument("-policy", "--policy", type=str, required=False, default='False')
    parser.add_argument("-endpoint", "--endpoint", type=str, required=False, default='False')
    parser.add_argument("-user", "--user", type=str, required=False, default="admin")
    parser.add_argument("-validation", "--validation", type=str, required=False, default='True')
    parser.add_argument("-password", "--password", type=str, default="ins3965!", required=False)
    args = parser.parse_args()
    return args

args = parse_args()
leaf1_ip = args.leaf1
leaf2_ip = args.leaf2
user = args.user
password = args.password
#password = getpass.getpass('Enter {} password for leaf node access: '.format(user))

if args.policy.lower() == 'true':
    isPolicyCache = True
elif args.policy.lower() == 'false':
    isPolicyCache = False
else:
    print(f"Invalid argument value {args.policy} - can only be 'true' or 'false' ")
    exit()

if args.endpoint.lower() == 'true':
    isEpCache = True
elif args.endpoint.lower() == 'false':
    isEpCache = False
else:
    print(f"Invalid argument value {args.endpoint} - can only be 'true' or 'false' ")
    exit()
    
if args.validation.lower() == 'true':
    isValidationRequired = True
elif args.validation.lower() == 'false':
    isValidationRequired = False
else:
    print(f"Invalid argument value {args.validation} - can only be 'true' or 'false' ")
    exit()

if isEpCache is False and isPolicyCache is False:
    isEpCache = True
    isPolicyCache = True

# Download leaf1 and leaf2 - policy cache
if isPolicyCache:
    cwd = os.getcwd()
    policy_cache1 = os.path.join(cwd, 'policycache1.json')
    policy_cache2 = os.path.join(cwd, 'policycache2.json')
    print("Downloading policy cache for leaf1...")
    dumpAndDownloadCache(leaf1_ip, user, password, 'policy', policy_cache1)
    print("Downloading policy cache for leaf2...")
    dumpAndDownloadCache(leaf2_ip, user, password, 'policy', policy_cache2)

# Download leaf1 and leaf2 - ep cache
if isEpCache:
    cwd = os.getcwd()
    ep_cache1 = os.path.join(cwd, 'epcache1.json')
    ep_cache2 = os.path.join(cwd, 'epcache2.json')
    print("Downloading ep cache for leaf1...")
    dumpAndDownloadCache(leaf1_ip, user, password, 'endpoint', ep_cache1)
    print("Downloading ep cache for leaf2...")
    dumpAndDownloadCache(leaf2_ip, user, password, 'endpoint', ep_cache2)

# Validate cache of leaf1 and leaf2
isPolicyCacheInconsistent = False
isEpCacheInconsistent = False
if isPolicyCache:
    print("Comparing policy cache...")
    isPolicyCacheInconsistent = compareCache(policy_cache1, policy_cache2, True)

if isEpCache:
    print("Comparing ep cache...")
    isEpCacheInconsistent = compareCache(ep_cache1, ep_cache2, False)
    
# Collect techsupport if cache is inconsistent
if isPolicyCacheInconsistent or isEpCacheInconsistent:
    print("Inconsistency found between caches, collecting techsupport...")
    collectTechsupport(leaf1_ip, user, password)
    collectTechsupport(leaf2_ip, user, password)
    print("Techsupport collection is completed!")
    print('----------------------------------------------------------------\n')



    `

// IdMap holds the mapping between IDs and strings
type IdMap struct {
	fileName  string
	id2strmap map[uint32]string
}

// NewIdMap initializes an IdMap from a file
func NewIdMap(data []byte) *IdMap {
	idMap := &IdMap{
		id2strmap: make(map[uint32]string),
	}
	offset := 12
	for offset < len(data) {
		key := binary.LittleEndian.Uint32(data[offset:])
		offset += 4

		sz := binary.LittleEndian.Uint16(data[offset:])
		offset += 2

		strData := data[offset : offset+int(sz)]
		str := string(strData)
		idMap.id2strmap[key] = str
		offset += int(sz)
	}

	return idMap
}

// IDToStr converts an ID to its corresponding string
func (idMap *IdMap) IDToStr(id uint32) (string, bool) {
	str, found := idMap.id2strmap[id]
	return str, found
}

// PrintID2StrMap prints the ID to string map
func (idMap *IdMap) PrintID2StrMap() {
	fmt.Println("/////////// id to str map /////////////")
	for k, v := range idMap.id2strmap {
		fmt.Println(k, v)
	}
}

// NodeIdMaps holds all ID maps unique to a particular node
type NodeIdMaps struct {
	nodeMaps map[string]map[string]*IdMap
}

// NewNodeIdMaps initializes a NodeIdMaps
func NewNodeIdMaps() *NodeIdMaps {
	return &NodeIdMaps{
		nodeMaps: make(map[string]map[string]*IdMap),
	}
}

func (nim *NodeIdMaps) AddIdMap(nodeName string, mapName string, idMap *IdMap) {
	if _, exists := nim.nodeMaps[nodeName]; !exists {
		nim.nodeMaps[nodeName] = make(map[string]*IdMap)
	}
	nim.nodeMaps[nodeName][mapName] = idMap
}

// GetIdMap retrieves an IdMap for a specific node and map name
func (nim *NodeIdMaps) GetIdMap(nodeName string, mapName string) (*IdMap, bool) {
	nodeMap, exists := nim.nodeMaps[nodeName]
	if !exists {
		return nil, false
	}

	idMap, exists := nodeMap[mapName]
	return idMap, exists
}

// Utility functions to map registers and metadata
func mapRegister(register string, bridgName string) string {
	if bridgName == "br-access" {
		return BrAccessRegisterMap[register]
	}
	return BrIntRegisterMap[register]
}

func mapRegToFileValue(register string, bridgName string) string {
	regfileval := ""
	if bridgName == "br-access" {
		if _, ok := BrAccessFileRegisterMap[register]; ok {
			regfileval = BrAccessFileRegisterMap[register]
		}
	} else {
		if _, ok := BrIntFilesRegisterMap[register]; ok {
			regfileval = BrIntFilesRegisterMap[register]
		}
	}
	return regfileval
}

func mapMetadata(metadata string, bridgName string) string {
	// Extract the metadata value from the entry

	metadataValue := strings.Split(metadata, "/")[0]

	// Map the metadata value to the metadata map
	if bridgName == "br-access" {

		if mappedName, found := BrAccessMetadataMap[metadataValue]; found {

			metadataValue = mappedName
		}
	} else {
		if mappedName, found := BrIntMetadataMap[metadataValue]; found {
			metadataValue = mappedName
		}
	}

	return metadataValue
}

func (br *Bridge) parseFlowEntries() map[int][]string {
	flowEntries := br.brFlows
	entries := strings.Split(flowEntries, "\n")
	tableMap := make(map[int][]string)
	var currentTable int

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if strings.HasPrefix(entry, "bridge") {
			continue
		}

		// Check if the entry starts with a table number
		if strings.Contains(entry, ". ") {
			parts := strings.SplitN(entry, ". ", 2)
			fmt.Sscanf(parts[0], "%d", &currentTable)
			entry = strings.TrimSpace(parts[1])
		}

		tableMap[currentTable] = append(tableMap[currentTable], entry)
	}

	return tableMap
}

func (br *Bridge) buildPacketTrace() string {
	flowEntries := br.brFlowEntries
	bridgName := br.br_type
	var buffer bytes.Buffer

	var summary *PacketSummary
	var inPort, outPort, tunnelID string
	var previousTable int

	var tableDescriptions map[int]string
	var lastTable int

	summary = &PacketSummary{}

	switch bridgName {
	case "br-access":
		tableDescriptions = brAccessTableDescriptions
		lastTable = LastTableNumBrAccess
	case "br-int":
		tableDescriptions = brIntTableDescriptions
		lastTable = LastTableNumBrInt

	}
	// Collect and sort the table numbers
	tableNumbers := make([]int, 0, len(flowEntries))
	for tableNumber := range flowEntries {
		tableNumbers = append(tableNumbers, tableNumber)
	}
	sort.Ints(tableNumbers)
	//fmt.Println(tableNumbers)
	// Iterate through the tables sequentially
	for _, table := range tableNumbers {
		fmt.Fprintf(&buffer, "%sTable %d: - %s%s\n", ColorYellow, table, tableDescriptions[table], ColorReset)
		for _, entry := range flowEntries[table] {
			// Split the entry into actions
			actions := strings.Split(entry, ", ")
			for _, action := range actions {
				action = strings.TrimSpace(action)

				// Check for metadata and register loading
				if strings.HasPrefix(action, "write_metadata:") {
					metadata := strings.Split(action, ":")[1]
					metadataValue := mapMetadata(metadata, bridgName)
					fmt.Fprintf(&buffer, "  Writing metadata: %s %s(%s)%s\n", metadata, ColorGreen, metadataValue, ColorReset)
				} else if strings.HasPrefix(action, "load:") {
					loadAction := strings.Split(action, "->")
					register := strings.Trim(loadAction[1], "[]")
					registerValue := mapRegister(register, bridgName)
					regfileval := mapRegToFileValue(register, bridgName)
					if regfileval != "" {
						id_hex := strings.Split(loadAction[0], ":")[1]
						num, err := strconv.ParseUint(id_hex[2:], 16, 32)
						if err != nil {
							fmt.Println("Error:", err)
						}
						id := uint32(num)
						pol_obj := nodeIdMaps.nodeMaps[br.nodename][regfileval].id2strmap[id]
						fmt.Fprintf(&buffer, "  Loading register: %s%s(%s)%s -> %s %s(%s)%s\n", loadAction[0], ColorPurple, pol_obj, ColorReset, register, ColorGreen, registerValue, ColorReset)
					} else {
						id_hex := strings.Split(loadAction[0], ":")[1]
						id_int, _ := strconv.ParseInt(id_hex, 0, 64)

						fmt.Fprintf(&buffer, "  Loading register: %s%s(%d)%s -> %s %s(%s)%s\n", loadAction[0], ColorPurple, id_int, ColorReset, register, ColorGreen, registerValue, ColorReset)
					}

					if bridgName == "br-int" && register == "NXM_NX_REG12" {
						ct_mark = strings.Split(loadAction[0], ":")[1]
					}

				} else if strings.HasPrefix(action, "goto_table:") {
					next_table := strings.Split(action, ":")[1]
					fmt.Fprintf(&buffer, "  Going to table: %s\n", next_table)
					previousTable = table
				} else if strings.HasPrefix(action, "output:") {
					output := strings.Split(action, ":")[1]
					if strings.HasPrefix(output, "NXM_NX_REG") {
						register := strings.Trim(output, "[]")
						registerValue := mapRegister(register, bridgName)
						outPort = registerValue
						fmt.Fprintf(&buffer, "  Output to: %s %s(%s)%s\n", output, ColorGreen, registerValue, ColorReset)
					} else {
						outPort = output
						out_port_name := findPortName(outPort, bridgName, br.ovsPod)
						fmt.Fprintf(&buffer, "  Output to port: %s->%s%s%s\n", output, ColorGreen, out_port_name, ColorReset)
						summary.OutPort = outPort
					}

				} else if strings.HasPrefix(action, "-> output") {
					outputParts := strings.Split(action, "->")

					if strings.Contains(outputParts[1], "to ") {
						outPort = strings.Split(outputParts[1], "to ")[1]
						//out_port_name := findPortName(outPort, bridgName, br.ovsPod)
						fmt.Fprintf(&buffer, " Out port:%s\n", outPort)
						summary.OutPort = outPort
					} else if strings.Contains(outputParts[1], "is ") {
						outPort = strings.Split(outputParts[1], "is ")[1]
						out_port_name := findPortName(outPort, bridgName, br.ovsPod)
						fmt.Fprintf(&buffer, " Out port:%s->%s%s%s\n", outPort, ColorGreen, out_port_name, ColorReset)
						summary.OutPort = outPort
					}

				} else if strings.HasPrefix(action, "in_port=") {
					inPort = strings.Split(action, "=")[1]
					inPort = strings.Split(inPort, ",")[0]
					in_port_name := findPortName(inPort, bridgName, br.ovsPod)
					fmt.Fprintf(&buffer, "  In port: %s->%s\n", inPort, in_port_name)
					summary.InPort = inPort
				} else if strings.HasPrefix(action, "move:") {
					moveAction := strings.Split(action, "->")
					moveSource := strings.Split(moveAction[0], ":")[1]
					moveTarget := strings.TrimSpace(moveAction[1])
					fmt.Fprintf(&buffer, "  Moving value from: %s to %s\n", moveSource, moveTarget)
				} else if strings.HasPrefix(action, "set_field:") {
					setFieldAction := strings.Split(action, "->")
					fieldName := strings.TrimSpace(setFieldAction[1])
					fieldValue := strings.TrimSpace(strings.Split(setFieldAction[0], "set_field:")[1])
					if fieldName == "tcp_dst" {
						summary.tcp_dst = fieldValue
					} else if fieldName == "ip_dst" {
						summary.ip_dst = fieldValue
					}
					fmt.Fprintf(&buffer, "  Setting field: %s to %s\n", fieldName, fieldValue)
				} else if strings.HasPrefix(action, "dec_ttl") {
					fmt.Fprintf(&buffer, "  Decrementing TTL\n")
				} else if strings.Contains(action, "-> NXM_NX_TUN_ID") {
					// Extract the value moved to the tunnel ID
					tunnelID = strings.Split(action, " is now ")[1]
					tunnelIDInt, _ := strconv.ParseInt(tunnelID, 0, 64)
					// Print the tunnel ID in both hexadecimal and decimal formats
					fmt.Fprintf(&buffer, "    VXLAN_Tunnel_ID is now %s %s(decimal: %d)%s\n", tunnelID, ColorGreen, tunnelIDInt, ColorReset)
					summary.TunnelID = fmt.Sprintf("VXLAN_Tunnel_ID:%s (decimal: %d)\n", tunnelID, tunnelIDInt)
				} else if strings.HasPrefix(action, "-> NXM_NX_TUN_IPV4_DST") {
					// Extract the value moved to the IPv4 destination address
					ipv4Dest := strings.Split(action, " is now ")[1]
					fmt.Fprintf(&buffer, "    IPv4 Destination is now %s\n", ipv4Dest)
				} else if strings.Contains(action, "nat(src=") && summary.snat_ip == "" {

					re := regexp.MustCompile(`nat\(src=(\d+\.\d+\.\d+\.\d+)`)

					match := re.FindStringSubmatch(action)
					if len(match) > 1 {
						ipAddress := match[1]
						fmt.Fprintf(&buffer, "%sSNAT IP is %s%s\n", ColorPurple, ipAddress, ColorReset)
						summary.snat_ip = ipAddress
					}
				} else if strings.Contains(action, "Final flow") || strings.Contains(action, "Megaflow") || strings.Contains(action, "Datapath actions") {
					continue
				} else { //if regexp.MustCompile(`reg\d+=`).MatchString(action) {
					re := regexp.MustCompile(`reg(\d+)=0x[0-9a-fA-F]+`)

					// Find all matches in the line
					matches := re.FindAllString(action, -1)
					for _, match := range matches {
						// Extract the register (e.g., "reg0")
						parts := strings.Split(match, "=")
						reg := parts[0]
						hex_val := parts[1]

						if register, ok := BrRegToNXMMap[reg]; ok {

							// Replace the register with the corresponding value from the map
							regfileval := mapRegToFileValue(register, bridgName)
							if regfileval != "" {
								//id_hex := val
								num, err := strconv.ParseUint(hex_val[2:], 16, 32)
								if err != nil {
									fmt.Println("Error:", err)
								}
								id := uint32(num)
								pol_obj := nodeIdMaps.nodeMaps[br.nodename][regfileval].id2strmap[id]
								replacement := fmt.Sprintf("%s=%s(%s)", reg, hex_val, pol_obj)
								org := fmt.Sprintf("%s=%s", reg, hex_val)
								action = strings.Replace(action, org, replacement, 1)
							}

						}
					}
					fmt.Fprintf(&buffer, "%s\n", action)
				}

			}
		}
		fmt.Fprintln(&buffer)
	}

	// Determine if the packet was dropped and update the summary
	if len(tableNumbers) > 0 && tableNumbers[len(tableNumbers)-1] == lastTable {
		summary.previousTable = previousTable
		summary.PacketDropped = true

	}

	br.summary = summary

	return buffer.String()
}

func findPortName(port string, bridgName string, ovspod string) string {
	port_buffer := new(bytes.Buffer)
	cmd_args := []string{"exec", "-n", "aci-containers-system", ovspod,
		"--", "/bin/sh", "-c", fmt.Sprintf("ovs-ofctl show %s", bridgName), "|", fmt.Sprintf("grep -E ' %s\\([^)]+\\):'", port)}
	err := execKubectl(cmd_args, port_buffer)
	if err != nil {
		return ""
	}
	if port_buffer.Len() > 0 {
		output := port_buffer.String()
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, " "+port+"(") {
				ports := strings.Split(line, ":")[0]
				port_name := strings.Split(ports, " "+port)[1]
				return port_name
			}
		}
	}
	return ""
}

func init() {
	PodtoPodtraceCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	PodtoPodtraceCmd.Flags().BoolVar(&tcpFlag, "tcp", false, "Specify if the protocol is TCP")
	PodtoPodtraceCmd.Flags().IntVar(&tcpSrc, "tcp_src", 0, "Specify the source TCP port")
	PodtoPodtraceCmd.Flags().IntVar(&tcpDst, "tcp_dst", 0, "Specify the destination TCP port")
	PodtoPodtraceCmd.Flags().BoolVar(&gbp, "gbp", false, "Enable GBP mode")
	PodtoPodtraceCmd.Flags().StringVar(&username, "username", "", "Username for APIC")
	PodtoPodtraceCmd.Flags().StringVar(&apic, "apic", "", "APIC IP address")
	PodtoPodtraceCmd.Flags().BoolVar(&policy, "policy", false, "Enable Policy Cache")
	PodtoPodtraceCmd.Flags().BoolVar(&endpoint, "endpoint", false, "Enable Endpoint Cache")

	PodtoSvctraceCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	PodtoSvctraceCmd.Flags().BoolVar(&tcpFlag, "tcp", false, "Specify if the protocol is TCP")
	PodtoSvctraceCmd.Flags().IntVar(&tcpSrc, "tcp_src", 0, "Specify the source TCP port")
	PodtoSvctraceCmd.Flags().IntVar(&tcpDst, "tcp_dst", 0, "Specify the destination TCP port")

	PodtoExttraceCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	PodtoExttraceCmd.Flags().BoolVar(&tcpFlag, "tcp", false, "Specify if the protocol is TCP")
	PodtoExttraceCmd.Flags().IntVar(&tcpSrc, "tcp_src", 0, "Specify the source TCP port")
	PodtoExttraceCmd.Flags().IntVar(&tcpDst, "tcp_dst", 0, "Specify the destination TCP port")

}

func isValidPort(port int) bool {
	return port > 0 && port <= 65535
}

func pod_to_pod_tracepacket(args []string, tcpFlag bool, tcpSrc int, tcpDst int, verbose bool, gbp, policy, endpoint bool, username string, apic string) {
	if tcpFlag {
		if tcpSrc == 0 && tcpDst == 0 {
			fmt.Printf("\n%sError: If tcp is specified, either tcp_src or tcp_dst must be provided.%s\n", ColorRed, ColorReset)
			return
		} else if tcpSrc == 0 {
			tcpSrc = 12345
		} else if tcpDst == 0 {
			tcpDst = 12345
		}

		if !isValidPort(tcpSrc) {
			fmt.Printf("\n%sError: Please enter tcp_src value in valid port range [1-65535].%s\n", ColorRed, ColorReset)
			return
		}

		if !isValidPort(tcpDst) {
			fmt.Printf("\n%sError: Please enter tcp_dst value in valid port range [1-65535].%s\n", ColorRed, ColorReset)
			return
		}

	}

	if !gbp && (policy || endpoint || len(apic) > 0 || len(username) > 0) {
		fmt.Printf("\n%sError: Please provide gbp flag to enable leafcache diff.%s\n", ColorRed, ColorReset)
		return
	}

	if gbp {
		if username == "" || apic == "" {
			fmt.Printf("\n%sError: If gbp is specified, username and apic must be provided.%s\n", ColorRed, ColorReset)
			return
		}

		if !policy && !endpoint {
			fmt.Printf("\n%sError: Please provide either policy or endpoint flag or both%s\n", ColorRed, ColorReset)
			return
		}

		var err error

		fmt.Print("Enter APIC password: ")
		apicpass, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			fmt.Println("Error reading APIC password:", err)
			return
		}
		apicpassword = string(apicpass)

		fmt.Println()

		fmt.Print("Enter Leaf password: ")
		leafpass, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			fmt.Println("Error reading Leaf password:", err)
			return
		}

		leafpassword = string(leafpass)

		fmt.Println()

	}

	srcnspod := args[0]
	dstnspod := args[1]
	var src_pod_hostnetwork bool
	var dst_pod_hostnetwork bool
	src_opflex_pod := ""
	dst_opflex_pod := ""
	var src_ep EndPoints
	var dst_ep EndPoints
	var egresspacketdropped bool
	var ingresspacketdropped bool
	sections := []string{}
	var tun_id string
	var tun_id_int int64
	var targetPort int32

	out_bridgeflows := []Bridge{}

	srcns, srcpodname, err := splitNamespaceAndPod(srcnspod)
	if err != nil {
		fmt.Println(err)
		return
	}

	destns, destpodname, err := splitNamespaceAndPod(dstnspod)
	if err != nil {
		fmt.Println(err)
		return
	}

	kubeClient := initClientPrintError()
	if kubeClient == nil {
		return
	}

	is_src_ns_valid := validNamespace(kubeClient, srcns)
	if !is_src_ns_valid {
		fmt.Fprintf(os.Stderr, "Could not find namespace: %s\n", srcns)
		return
	}

	is_dest_ns_valid := validNamespace(kubeClient, destns)
	if !is_dest_ns_valid {
		fmt.Fprintf(os.Stderr, "Could not find namespace: %s\n", destns)
		return
	}

	srcPod, err := getPod(kubeClient, srcns, srcpodname)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not find source pod:", err)
		return
	}

	dstPod, err := getPod(kubeClient, destns, destpodname)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not find destination pod:", err)
		return
	}

	if tcpFlag {
		for _, container := range dstPod.Spec.Containers {
			for _, port := range container.Ports {
				if port.ContainerPort == int32(tcpDst) {
					targetPort = port.ContainerPort
				}
			}
		}

		if targetPort == 0 {
			fmt.Printf("\n%sNo process is running on tcp port %d on the destination pod %s\n", ColorRed, tcpDst, ColorReset)
			return
		}
	}

	src_node, err := kubeClient.CoreV1().Nodes().Get(kubecontext.TODO(), srcPod.Spec.NodeName, metav1.GetOptions{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not find source node:", err)
		return
	}

	if podIPMatchesNodeIP(srcPod.Status.PodIP, src_node.Status.Addresses) {
		src_pod_hostnetwork = true
	}

	dst_node, err := kubeClient.CoreV1().Nodes().Get(kubecontext.TODO(), dstPod.Spec.NodeName, metav1.GetOptions{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not find destination node:", err)
		return
	}

	if podIPMatchesNodeIP(dstPod.Status.PodIP, dst_node.Status.Addresses) {
		dst_pod_hostnetwork = true
	}

	srcOvsPodName, err := podForNode(kubeClient, "aci-containers-system",
		srcPod.Spec.NodeName, "name=aci-containers-openvswitch")

	if err != nil {
		fmt.Fprintln(os.Stderr, err, " which has label aci-containers-openvswitch")
		return
	}

	destOvsPodName := ""
	if dstPod.Spec.NodeName != srcPod.Spec.NodeName {
		destOvsPodName, err = podForNode(kubeClient, "aci-containers-system",
			dstPod.Spec.NodeName, "name=aci-containers-openvswitch")

		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	} else {
		destOvsPodName = srcOvsPodName
	}

	src_opflex_pod, err = podForNode(kubeClient, "aci-containers-system",
		srcPod.Spec.NodeName, "name=aci-containers-host")

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	dst_opflex_pod, err = podForNode(kubeClient, "aci-containers-system",
		dstPod.Spec.NodeName, "name=aci-containers-host")

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	if !src_pod_hostnetwork {
		src_ep, err = findEpFile(srcPod, src_opflex_pod)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return

		}
	}

	if !dst_pod_hostnetwork {
		dst_ep, err = findEpFile(dstPod, dst_opflex_pod)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)

		}

	}

	if _, ok := nodeIdMaps.nodeMaps[srcPod.Spec.NodeName]; !ok {
		err := buildIdMaps(srcPod.Spec.NodeName, src_opflex_pod)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return

		}
	}

	if !dst_pod_hostnetwork {
		//Find gbpObjects
		gbpObjects, err := findGbpPolicy(kubeClient, dstPod)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}

		//Destination Calculation
		tun_id, err = findTunnelId(gbpObjects, dst_ep)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}

		tun_id_int, _ = strconv.ParseInt("0x"+tun_id, 0, 64)
	}

	//Source Calculation
	src_buffer := new(bytes.Buffer)

	cmd_args := []string{}

	fmt.Printf("\n\n%s%s%s", ColorGreen, "\nSummary\n", ColorReset)

	printACIDiagram()

	if !src_pod_hostnetwork {
		// Print the EP details
		printEndpointDetails(src_ep, srcPod, src_opflex_pod)
	}

	if !dst_pod_hostnetwork {
		// Print the EP details
		printEndpointDetails(dst_ep, dstPod, dst_opflex_pod)
	}

	if !src_pod_hostnetwork {
		if !dst_pod_hostnetwork {
			if !tcpFlag {
				cmd_args = []string{"exec", "-n", "aci-containers-system", srcOvsPodName,
					"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-access 'in_port=%s, ip, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s'", src_ep.Attributes.InterfaceName,
						srcPod.Status.PodIP, dstPod.Status.PodIP, src_ep.Mac, dst_ep.Mac)}
			} else {
				cmd_args = []string{"exec", "-n", "aci-containers-system", srcOvsPodName,
					"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-access 'in_port=%s, tcp, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s,tcp_src=%d,tcp_dst=%d'", src_ep.Attributes.InterfaceName,
						srcPod.Status.PodIP, dstPod.Status.PodIP, src_ep.Mac, dst_ep.Mac, tcpSrc, tcpDst)}
			}
		} else {
			dst_mac := new(bytes.Buffer)
			dst_agrs := []string{"exec", "-n", "aci-containers-system", destOvsPodName,
				"--", "/bin/sh", "-c", fmt.Sprintf("ifconfig | grep -A5 'inet %s' | grep -oE '([0-9a-fA-F]{2}:){5}([0-9a-fA-F]{2})'", dstPod.Status.PodIP)}

			err = execKubectl(dst_agrs, dst_mac)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return

			}

			if !tcpFlag {
				cmd_args = []string{"exec", "-n", "aci-containers-system", srcOvsPodName,
					"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-access 'in_port=%s, ip, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s'", src_ep.Attributes.InterfaceName,
						srcPod.Status.PodIP, dstPod.Status.PodIP, src_ep.Mac, dst_mac)}

			} else {
				cmd_args = []string{"exec", "-n", "aci-containers-system", srcOvsPodName,
					"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-access 'in_port=%s, tcp, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s,tcp_src=%d,tcp_dst=%d'", src_ep.Attributes.InterfaceName,
						srcPod.Status.PodIP, dstPod.Status.PodIP, src_ep.Mac, dst_mac, tcpSrc, tcpDst)}
			}

		}

		err = execKubectl(cmd_args, src_buffer)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return

		}

		sections = strings.Split(src_buffer.String(), "bridge")

		for idx, section := range sections {
			if strings.Contains(section, "br-access") {
				out_bridgeflows = append(out_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" + section, nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
			} else if strings.Contains(section, "br-int") {
				out_bridgeflows = append(out_bridgeflows, Bridge{br_type: "br-int", brFlows: "bridge" + section, nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
			}

			if idx > 0 && strings.Contains(sections[idx-1], "br-access") && strings.Contains(sections[idx-1], "resume conntrack") {
				out_bridgeflows[len(out_bridgeflows)-1].br_type = "br-access"
			}

			if idx > 0 && strings.Contains(sections[idx-1], "br-int") && strings.Contains(sections[idx-1], "resume conntrack") {
				out_bridgeflows[len(out_bridgeflows)-1].br_type = "br-int"
			}
		}

		for idx, _ := range out_bridgeflows {
			out_bridgeflows[idx].brFlowEntries = out_bridgeflows[idx].parseFlowEntries()
			out_bridgeflows[idx].out_br_buff = out_bridgeflows[idx].buildPacketTrace()
		}

		for _, br := range out_bridgeflows {
			if br.summary != nil && br.summary.PacketDropped {
				if br.br_type == "br-access" {
					fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n", ColorRed, "br-access", br.summary.previousTable, brAccessTableDescriptions[br.summary.previousTable], srcPod.Spec.NodeName, ColorReset)
					egresspacketdropped = true
				} else {
					fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n", ColorRed, "br-int", br.summary.previousTable, brIntTableDescriptions[br.summary.previousTable], srcPod.Spec.NodeName, ColorReset)
					egresspacketdropped = true
				}
			}
		}

		if !dst_pod_hostnetwork {
			if !egresspacketdropped {
				if srcPod.Spec.NodeName != dstPod.Spec.NodeName {
					fmt.Printf("%s=> Packet sent out from node:%s with source_epg %s(%s) to destination_epg with VXLAN_Tunnel_ID:0x%s(decimal:%d)(%s) %s\n",
						ColorGreen, srcPod.Spec.NodeName, out_bridgeflows[len(out_bridgeflows)-1].summary.TunnelID, src_ep.EndpointGroupName, tun_id, tun_id_int, dst_ep.EndpointGroupName, ColorReset)
				} else {
					fmt.Printf("%s=> Packet sent out and recieved on same node: %s%s\n", ColorGreen, srcPod.Spec.NodeName, ColorReset)
				}
			}
		} else {
			if !egresspacketdropped {
				if srcPod.Spec.NodeName != dstPod.Spec.NodeName {
					fmt.Printf("%s=> Packet sent out from node:%s with source_epg %s(%s) to destination pod IP (%s) on the node(%s) network %s\n",
						ColorGreen, srcPod.Spec.NodeName, out_bridgeflows[len(out_bridgeflows)-1].summary.TunnelID, src_ep.EndpointGroupName, dstPod.Status.PodIP, dstPod.Spec.NodeName, ColorReset)
				} else {
					fmt.Printf("%s=> Packet sent out and recieved on same node: %s%s\n", ColorGreen, srcPod.Spec.NodeName, ColorReset)
				}
			}
		}

	} else {
		if !dst_pod_hostnetwork {
			if srcPod.Spec.NodeName != dstPod.Spec.NodeName {
				fmt.Printf("%s=> Packet sent out from source pod IP (%s) on the node(%s) with node network to destination pod IP (%s) on the node(%s) %s\n",
					ColorGreen, srcPod.Status.PodIP, srcPod.Spec.NodeName, dstPod.Status.PodIP, dstPod.Spec.NodeName, ColorReset)
			} else {
				fmt.Printf("%s=> Packet sent out and recieved on same node: %s%s\n", ColorGreen, srcPod.Spec.NodeName, ColorReset)
			}
		} else {
			if srcPod.Spec.NodeName != dstPod.Spec.NodeName {
				fmt.Printf("%s=> Packet sent out from source pod IP (%s) on the node(%s) with node network to destination pod IP (%s) on the node(%s) network %s\n",
					ColorGreen, srcPod.Status.PodIP, srcPod.Spec.NodeName, dstPod.Status.PodIP, dstPod.Spec.NodeName, ColorReset)
			} else {
				fmt.Printf("%s=> Packet sent out and recieved on same node: %s%s\n", ColorGreen, srcPod.Spec.NodeName, ColorReset)
			}
		}
	}

	/////////////////////////////////Incoming Traffic//////////////////////
	in_bridgeflows := []Bridge{}

	if !egresspacketdropped {

		if _, ok := nodeIdMaps.nodeMaps[dstPod.Spec.NodeName]; !ok {
			err := buildIdMaps(dstPod.Spec.NodeName, dst_opflex_pod)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}
		}

		dest_buffer := new(bytes.Buffer)
		if !dst_pod_hostnetwork {
			if !src_pod_hostnetwork {
				if srcPod.Spec.NodeName != dstPod.Spec.NodeName {
					if !tcpFlag {
						cmd_args = []string{"exec", "-n", "aci-containers-system", destOvsPodName,
							"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-int 'in_port=vxlan0,tun_id=0x%s, ip, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s'",
								tun_id, srcPod.Status.PodIP, dstPod.Status.PodIP, src_ep.Mac, dst_ep.Mac)}
					} else {
						cmd_args = []string{"exec", "-n", "aci-containers-system", destOvsPodName,
							"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-int 'in_port=vxlan0,tun_id=0x%s, tcp, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s,tcp_src=%d,tcp_dst=%d'",
								tun_id, srcPod.Status.PodIP, dstPod.Status.PodIP, src_ep.Mac, dst_ep.Mac, tcpSrc, tcpDst)}
					}
				}

			} else {
				//src_mac := new(bytes.Buffer)
				//src_agrs := []string{"exec", "-n", "aci-containers-system", srcOvsPodName,
				//	"--", "/bin/sh", "-c", fmt.Sprintf("ifconfig | grep -A5 'inet %s' | grep -oE '([0-9a-fA-F]{2}:){5}([0-9a-fA-F]{2})'", srcPod.Status.PodIP)}
				//
				//err = execKubectl(src_agrs, src_mac)
				//if err != nil {
				//	fmt.Fprintln(os.Stderr, err)
				//	return
				//
				//}
				if !tcpFlag {
					cmd_args = []string{"exec", "-n", "aci-containers-system", destOvsPodName,
						"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-int 'in_port=vxlan0,tun_id=0x%s, ip, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s'",
							tun_id, srcPod.Status.PodIP, dstPod.Status.PodIP, "00:22:bd:f8:19:ff", dst_ep.Mac)}
				} else {
					cmd_args = []string{"exec", "-n", "aci-containers-system", destOvsPodName,
						"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-int 'in_port=vxlan0,tun_id=0x%s, tcp, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s,tcp_src=%d,tcp_dst=%d'",
							tun_id, srcPod.Status.PodIP, dstPod.Status.PodIP, "00:22:bd:f8:19:ff", dst_ep.Mac, tcpSrc, tcpDst)}
				}
			}

			err = execKubectl(cmd_args, dest_buffer)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}

			sections = strings.Split(dest_buffer.String(), "bridge")

			for idx, section := range sections {
				if strings.Contains(section, "br-access") {
					in_bridgeflows = append(in_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" + section, nodename: dstPod.Spec.NodeName, ovsPod: destOvsPodName, opflexPod: dst_opflex_pod})
				} else if strings.Contains(section, "br-int") {
					in_bridgeflows = append(in_bridgeflows, Bridge{br_type: "br-int", brFlows: "bridge" + section, nodename: dstPod.Spec.NodeName, ovsPod: destOvsPodName, opflexPod: dst_opflex_pod})
				}

				if idx > 0 && strings.Contains(sections[idx-1], "br-access") && strings.Contains(sections[idx-1], "resume conntrack") {
					in_bridgeflows[len(in_bridgeflows)-1].br_type = "br-access"
				}

				if idx > 0 && strings.Contains(sections[idx-1], "br-int") && strings.Contains(sections[idx-1], "resume conntrack") {
					in_bridgeflows[len(in_bridgeflows)-1].br_type = "br-int"
				}
			}

			for idx, _ := range in_bridgeflows {
				in_bridgeflows[idx].brFlowEntries = in_bridgeflows[idx].parseFlowEntries()
				in_bridgeflows[idx].out_br_buff = in_bridgeflows[idx].buildPacketTrace()
			}

			for _, br := range in_bridgeflows {
				if br.summary != nil && br.summary.PacketDropped {
					if br.br_type == "br-int" {
						fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n", ColorRed, "br-int", br.summary.previousTable, brIntTableDescriptions[br.summary.previousTable], dstPod.Spec.NodeName, ColorReset)
						ingresspacketdropped = true

					} else {
						fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n", ColorRed, "br-access", br.summary.previousTable, brAccessTableDescriptions[br.summary.previousTable], dstPod.Spec.NodeName, ColorReset)
						ingresspacketdropped = true
					}
				}
			}

			if !ingresspacketdropped && srcPod.Spec.NodeName != dstPod.Spec.NodeName {
				fmt.Printf("%s=> Packet recieved on node:%s with TunID: %s%s\n", ColorGreen, dstPod.Spec.NodeName, tun_id, ColorReset)
			}
		}

	}

	if verbose {
		//fmt.Printf("\n\n%s%s%s\n", ColorGreen, "Detailed Explanation", ColorReset)
		if !src_pod_hostnetwork {
			fmt.Printf("\n\n%s%s%s%s\n", ColorGreen, "Outgoing Packet from node: ", src_node.Name, ColorReset)
			for _, br := range out_bridgeflows {
				if br.br_type == "br-access" {
					fmt.Printf("\n%s%s%s\n", ColorYellow, "br-access:", ColorReset)
					fmt.Println(br.out_br_buff)
				} else {
					fmt.Printf("\n%s%s%s\n", ColorYellow, "br-int:", ColorReset)
					fmt.Println(br.out_br_buff)
				}

			}
		}

		if !dst_pod_hostnetwork && !egresspacketdropped && (srcPod.Spec.NodeName != dstPod.Spec.NodeName || src_pod_hostnetwork) {
			fmt.Printf("\n\n%s%s%s%s\n", ColorGreen, "Incoming Packet to node: ", dst_node.Name, ColorReset)
			for _, br := range in_bridgeflows {
				if br.br_type == "br-access" {
					fmt.Printf("\n%s%s%s\n", ColorYellow, "br-access:", ColorReset)
					fmt.Println(br.out_br_buff)
				} else {
					fmt.Printf("\n%s%s%s\n", ColorYellow, "br-int:", ColorReset)
					fmt.Println(br.out_br_buff)
				}

			}
		}
	}

	if gbp {
		if src_pod_hostnetwork && dst_pod_hostnetwork {
			fmt.Printf("\n\n%s%s%s\n\n", ColorRed, "Could not find LeafCache Diff since both pods are running on the node network", ColorRed)
			return
		}

		fmt.Printf("\n\n%s%s\n\n", ColorYellow, "Leaf Cache Summary")

		if !src_pod_hostnetwork && !dst_pod_hostnetwork {
			if srcPod.Spec.NodeName != dstPod.Spec.NodeName {

				// Step 1: Authenticate and get token
				token, err := getAPICAuthToken(username, apicpassword, apic, srcOvsPodName)
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error getting token:", err, ". Check Username, Apic IP and APIC/Leaf Passwords")
					return
				}

				// Step 2: Query for DN using the token
				srcDn, err := queryOpflexIDEpDN(token, apic, srcOvsPodName, srcPod, src_ep)
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error querying DN:", err)
					return

				}

				// Print or use dn as needed
				fmt.Println("Source Pod DN Topology is:", srcDn)

				destDn, err := queryOpflexIDEpDN(token, apic, destOvsPodName, dstPod, dst_ep)
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error querying DN:", err)
					return
				}

				// Print or use dn as needed
				fmt.Println("Dest Pod DN Topology is:", destDn)

				if reflect.DeepEqual(srcDn, destDn) {
					fmt.Println("Source and Destination DN Topology are same")
					src_leafs_ip_address := []string{}

					for _, DNs := range srcDn {
						leaf_ip_address, err := getNodeAddress(token, srcOvsPodName, apic, DNs)
						if err != nil {
							fmt.Fprintln(os.Stderr, "Error getting node address:", err)
							return
						} else {
							if len(leaf_ip_address) > 0 {
								src_leafs_ip_address = append(src_leafs_ip_address, leaf_ip_address)
							}
						}
					}

					fmt.Println("Source/Destination Pod leaf pairs IPs are:", src_leafs_ip_address)
					_, err := getLeafCacheDiff(src_leafs_ip_address, srcOvsPodName, username, leafpassword, policy, endpoint)
					if err != nil {
						fmt.Fprintln(os.Stderr, "Error getting source leafs cache", err)
						return
					}

					err = getLeafCacheDiffFiles(srcPod.Spec.NodeName, srcOvsPodName, policy, endpoint)
					if err != nil {
						fmt.Fprintln(os.Stderr, "Error getting leafs cache files", err)
						return
					}

				} else {
					fmt.Println("Source and Destination DN Topology are not same")
					src_leafs_ip_address := []string{}
					dest_leafs_ip_address := []string{}

					for _, DNs := range srcDn {
						leaf_ip_address, err := getNodeAddress(token, srcOvsPodName, apic, DNs)
						if err != nil {
							fmt.Fprintln(os.Stderr, "Error getting node address:", err)
							return
						} else {
							if len(leaf_ip_address) > 0 {
								src_leafs_ip_address = append(src_leafs_ip_address, leaf_ip_address)
							}
						}
					}

					fmt.Println("Source Pod leaf pairs IPs are:", src_leafs_ip_address)

					_, err := getLeafCacheDiff(src_leafs_ip_address, srcOvsPodName, username, leafpassword, policy, endpoint)
					if err != nil {
						fmt.Fprintln(os.Stderr, "Error getting source leafs cache", err)
						return
					}

					err = getLeafCacheDiffFiles(srcPod.Spec.NodeName, srcOvsPodName, policy, endpoint)
					if err != nil {
						fmt.Fprintln(os.Stderr, "Error getting leafs cache files", err)
						return
					}

					for _, DNs := range destDn {
						leaf_ip_address, err := getNodeAddress(token, destOvsPodName, apic, DNs)
						if err != nil {
							fmt.Fprintln(os.Stderr, "Error getting node address:", err)
							return
						} else {
							if len(leaf_ip_address) > 0 {
								dest_leafs_ip_address = append(dest_leafs_ip_address, leaf_ip_address)
							}
						}
					}

					fmt.Println("Destination Pod leaf pairs IPs are:", dest_leafs_ip_address)

					_, err = getLeafCacheDiff(dest_leafs_ip_address, destOvsPodName, username, leafpassword, policy, endpoint)
					if err != nil {
						fmt.Fprintln(os.Stderr, "Error getting destination leafs cache", err)
						return
					}

					err = getLeafCacheDiffFiles(dstPod.Spec.NodeName, destOvsPodName, policy, endpoint)
					if err != nil {
						fmt.Fprintln(os.Stderr, "Error getting leafs cache files", err)
						return
					}
				}

			} else {
				// Step 1: Authenticate and get token
				token, err := getAPICAuthToken(username, apicpassword, apic, srcOvsPodName)
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error getting token:", err)
					return
				}
				// Step 2: Query for DN using the token
				srcDn, err := queryOpflexIDEpDN(token, apic, srcOvsPodName, srcPod, src_ep)
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error querying DN:", err)
					return
				}

				// Print or use dn as needed
				fmt.Println("Source/Destination Pod DN Topology are:", srcDn)

				src_leafs_ip_address := []string{}

				for _, DNs := range srcDn {
					leaf_ip_address, err := getNodeAddress(token, srcOvsPodName, apic, DNs)
					if err != nil {
						fmt.Fprintln(os.Stderr, "Error getting node address:", err)
						return
					} else {
						if len(leaf_ip_address) > 0 {
							src_leafs_ip_address = append(src_leafs_ip_address, leaf_ip_address)
						}
					}
				}

				fmt.Println("Source/Destination Pod leaf pairs IPs are:", src_leafs_ip_address)

				_, err = getLeafCacheDiff(src_leafs_ip_address, srcOvsPodName, username, leafpassword, policy, endpoint)
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error getting leaf cache", err)
					return
				}

				err = getLeafCacheDiffFiles(dstPod.Spec.NodeName, destOvsPodName, policy, endpoint)
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error getting leafs cache files", err)
					return
				}

			}
		} else if !src_pod_hostnetwork {
			// Step 1: Authenticate and get token
			token, err := getAPICAuthToken(username, apicpassword, apic, srcOvsPodName)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error getting token:", err)
				return
			}
			// Step 2: Query for DN using the token
			srcDn, err := queryOpflexIDEpDN(token, apic, srcOvsPodName, srcPod, src_ep)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error querying DN:", err)
				return
			}

			// Print or use dn as needed
			fmt.Println("Source Pod DN Topology is:", srcDn)

			src_leafs_ip_address := []string{}

			for _, DNs := range srcDn {
				leaf_ip_address, err := getNodeAddress(token, srcOvsPodName, apic, DNs)
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error getting node address:", err)
					return
				} else {
					if len(leaf_ip_address) > 0 {
						src_leafs_ip_address = append(src_leafs_ip_address, leaf_ip_address)
					}
				}
			}

			fmt.Println("Source Pod leaf pairs IPs are:", src_leafs_ip_address)

			_, err = getLeafCacheDiff(src_leafs_ip_address, srcOvsPodName, username, leafpassword, policy, endpoint)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error getting leaf cache", err)
				return
			}

			err = getLeafCacheDiffFiles(srcPod.Spec.NodeName, srcOvsPodName, policy, endpoint)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error getting leafs cache files", err)
				return
			}

		} else if !dst_pod_hostnetwork {
			// Step 1: Authenticate and get token
			token, err := getAPICAuthToken(username, apicpassword, apic, srcOvsPodName)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error getting token:", err)
				return
			}
			destDn, err := queryOpflexIDEpDN(token, apic, destOvsPodName, dstPod, dst_ep)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error querying DN:", err)
				return
			}

			// Print or use dn as needed
			fmt.Println("Dest Pod DN Topology is:", destDn)

			dest_leafs_ip_address := []string{}

			for _, DNs := range destDn {
				leaf_ip_address, err := getNodeAddress(token, destOvsPodName, apic, DNs)
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error getting node address:", err)
					return
				} else {
					if len(leaf_ip_address) > 0 {
						dest_leafs_ip_address = append(dest_leafs_ip_address, leaf_ip_address)
					}
				}
			}

			fmt.Println("Destination Pod leaf pairs IPs are:", dest_leafs_ip_address)

			_, err = getLeafCacheDiff(dest_leafs_ip_address, destOvsPodName, username, leafpassword, policy, endpoint)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error getting destination leafs cache", err)
				return
			}

			err = getLeafCacheDiffFiles(dstPod.Spec.NodeName, destOvsPodName, policy, endpoint)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error getting leafs cache files", err)
				return
			}
		}
	}
	fmt.Printf("%s", ColorReset)
}

func podIPMatchesNodeIP(podIP string, nodeAddresses []v1.NodeAddress) bool {
	for _, addr := range nodeAddresses {
		if addr.Type == v1.NodeInternalIP || addr.Type == v1.NodeExternalIP {
			if addr.Address == podIP {
				return true
			}
		}
	}
	return false
}

func getAPICAuthToken(username, password, apic string, ovsPodName string) (string, error) {

	cmd_args := []string{
		"exec", "-n", "aci-containers-system", ovsPodName,
		"--", "/bin/sh", "-c", fmt.Sprintf("curl -s -k -X POST 'https://%s/api/aaaLogin.json' -d '{ \"aaaUser\": { \"attributes\": { \"name\": \"%s\", \"pwd\": \"%s\" } } }'", apic, username, password),
	}

	buffer := new(bytes.Buffer)
	err := execKubectl(cmd_args, buffer)
	if err != nil {
		return "", err
	}

	var resp struct {
		Imdata []struct {
			AaaLogin struct {
				Attributes struct {
					Token string `json:"token"`
				} `json:"attributes"`
			} `json:"aaaLogin"`
		} `json:"imdata"`
	}
	err = json.Unmarshal(buffer.Bytes(), &resp)
	if err != nil {
		return "", err
	}

	if len(resp.Imdata) > 0 {
		if resp.Imdata[0].AaaLogin.Attributes.Token != "" {
			return resp.Imdata[0].AaaLogin.Attributes.Token, nil
		}
	}
	return "", fmt.Errorf("token not found in response")
}

func getNodeAddress(token, ovsPodName string, apic, nodeDn string) (string, error) {

	query := fmt.Sprintf(`curl -s -k -X GET 'https://%s/api/class/mgmtRsOoBStNode.json?query-target-filter=eq(mgmtRsOoBStNode.tDn,"%s")' -b "APIC-Cookie=%s"`, apic, nodeDn, token)

	cmd_args := []string{"exec", "-n", "aci-containers-system", ovsPodName,
		"--", "/bin/sh", "-c", query}

	buffer := new(bytes.Buffer)
	err := execKubectl(cmd_args, buffer)
	if err != nil {
		return "", err
	}

	var resp struct {
		Imdata []struct {
			MgmtRsOoBStNode struct {
				Attributes struct {
					Addr string `json:"addr"`
				} `json:"attributes"`
			} `json:"mgmtRsOoBStNode"`
		} `json:"imdata"`
	}

	err = json.Unmarshal(buffer.Bytes(), &resp)
	if err != nil {
		return "", err
	}

	if len(resp.Imdata) > 0 {
		return strings.Split(resp.Imdata[0].MgmtRsOoBStNode.Attributes.Addr, "/")[0], nil
	}
	return "", fmt.Errorf("IP address not found in response")
}

func queryOpflexIDEpDN(token, apic string, ovsPodName string, pod *v1.Pod, ep EndPoints) ([]string, error) {

	query := fmt.Sprintf(`curl -s -k -X GET 'https://%s/api/class/opflexIDEp.json?query-target-filter=and(eq(opflexIDEp.containerName,"%s"),eq(opflexIDEp.namespace,"%s"),eq(opflexIDEp.epgID,"%s"))' -b 'APIC-Cookie=%s'`,
		apic, pod.Name, pod.Namespace, ep.EgPolicySpace+"_"+strings.Replace(ep.EndpointGroupName, "|", "_", -1), token)

	cmd_args := []string{"exec", "-n", "aci-containers-system", ovsPodName,
		"--", "/bin/sh", "-c", query}

	buffer := new(bytes.Buffer)
	err := execKubectl(cmd_args, buffer)
	if err != nil {
		return []string{}, err
	}

	var resp struct {
		Imdata []struct {
			OpflexIDEp struct {
				Attributes struct {
					Dn string `json:"dn"`
				} `json:"attributes"`
			} `json:"opflexIDEp"`
		} `json:"imdata"`
	}

	err = json.Unmarshal(buffer.Bytes(), &resp)
	if err != nil {
		return []string{}, err
	}

	if len(resp.Imdata) > 0 {
		var dns []string
		for _, item := range resp.Imdata {
			dn := strings.Split(item.OpflexIDEp.Attributes.Dn, "/sys")[0]
			dns = append(dns, dn)
		}

		return dns, nil
	}
	return []string{}, fmt.Errorf("DNs not found in response")
}

func getLeafCacheDiff(Dn []string, ovsPodName, username, password string, policy, endpoint bool) (string, error) {
	fmt.Println("\n\nRunning LeafCacheDiff script .........................")
	cmd_args := []string{}
	tmpFile, err := ioutil.TempFile("", "temp-script-*.py")
	if err != nil {
		fmt.Println("Error creating temp file:", err)
		return "", err
	}
	defer tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(script)); err != nil {
		fmt.Println("Error writing to temp file:", err)
		return "", err
	}

	cpCmd := exec.Command("kubectl", "cp", tmpFile.Name(), fmt.Sprintf("%s/%s:/tmp/script.py", "aci-containers-system", ovsPodName))
	if output, err := cpCmd.CombinedOutput(); err != nil {
		fmt.Println("Error copying file to pod:", err)
		fmt.Println(string(output))
		return "", err
	}

	if policy && endpoint {
		cmd_args = []string{"exec", "-n", "aci-containers-system", ovsPodName,
			"--", "/bin/sh", "-c", fmt.Sprintf(`python -u /tmp/script.py -leaf1 %s -leaf2 %s -user %s -password %s -policy True -endpoint True -validation False`, Dn[0], Dn[1], username, password)}
	} else if policy {
		cmd_args = []string{"exec", "-n", "aci-containers-system", ovsPodName,
			"--", "/bin/sh", "-c", fmt.Sprintf(`python -u /tmp/script.py -leaf1 %s -leaf2 %s -user %s -password %s -policy True -validation False`, Dn[0], Dn[1], username, password)}
	} else {
		cmd_args = []string{"exec", "-n", "aci-containers-system", ovsPodName,
			"--", "/bin/sh", "-c", fmt.Sprintf(`python -u /tmp/script.py -leaf1 %s -leaf2 %s -user %s -password %s -endpoint True -validation False`, Dn[0], Dn[1], username, password)}
	}

	buffer := new(bytes.Buffer)

	err = execStream(cmd_args, buffer)
	if err != nil {
		return "", err
	}

	return buffer.String(), nil
}

func execStream(args []string, buffer *bytes.Buffer) error {
	cmd := exec.Command("kubectl", args...)

	// Set stdout and stderr to os.Stdout and os.Stderr to stream output directly
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Start the command
	if err := cmd.Start(); err != nil {
		fmt.Printf("Error starting command: %v\n", err)
		return err
	}

	// Wait for the command to finish
	if err := cmd.Wait(); err != nil {
		fmt.Printf("Error waiting for command: %v\n", err)
		return err
	}

	return nil
}

func getLeafCacheDiffFiles(nodeName, ovsPodName string, policy, endpoint bool) error {

	var cpCmd *exec.Cmd

	if policy {
		cpCmd = exec.Command("kubectl", "cp", fmt.Sprintf("%s/%s:/policycache1.json", "aci-containers-system", ovsPodName), fmt.Sprintf("%s-policycache1.json", nodeName))
		if output, err := cpCmd.CombinedOutput(); err != nil {
			fmt.Println("Error copying file from pod to localfs:", err)
			fmt.Println(string(output))
			return err
		}

		cpCmd = exec.Command("kubectl", "cp", fmt.Sprintf("%s/%s:/policycache2.json", "aci-containers-system", ovsPodName), fmt.Sprintf("%s-policycache2.json", nodeName))
		if output, err := cpCmd.CombinedOutput(); err != nil {
			fmt.Println("Error copying file from pod to localfs:", err)
			fmt.Println(string(output))
			return err
		}
	}

	if endpoint {
		cpCmd = exec.Command("kubectl", "cp", fmt.Sprintf("%s/%s:/epcache1.json", "aci-containers-system", ovsPodName), fmt.Sprintf("%s-epcache1.json", nodeName))
		if output, err := cpCmd.CombinedOutput(); err != nil {
			fmt.Println("Error copying file from pod to localfs:", err)
			fmt.Println(string(output))
			return err
		}

		cpCmd = exec.Command("kubectl", "cp", fmt.Sprintf("%s/%s:/epcache2.json", "aci-containers-system", ovsPodName), fmt.Sprintf("%s-epcache2.json", nodeName))
		if output, err := cpCmd.CombinedOutput(); err != nil {
			fmt.Println("Error copying file from pod to localfs:", err)
			fmt.Println(string(output))
			return err
		}
	}

	cpCmd = exec.Command("kubectl", "cp", fmt.Sprintf("%s/%s:/difference.json", "aci-containers-system", ovsPodName), fmt.Sprintf("%s-difference.json", nodeName))
	if output, err := cpCmd.CombinedOutput(); err != nil {
		fmt.Println("Error copying file from pod to localfs:", err)
		fmt.Println(string(output))
		return err
	}

	return nil
}

func pod_to_svc_tracepacket(args []string, tcpFlag bool, tcpSrc int, tcpDst int, verbose bool) {
	if tcpFlag {
		if tcpSrc == 0 && tcpDst == 0 {
			fmt.Println("Error: If tcp is specified then tcp_dst must be provided.")
			return
		} else if tcpSrc == 0 {
			tcpSrc = 12345
		}

		if !isValidPort(tcpSrc) {
			fmt.Println("Error: Please enter tcpSrc value in valid port range [1-65535].")
			return
		}

		if !isValidPort(tcpDst) {
			fmt.Println("Error: Please enter tcpDst value in valid port range [1-65535].")
			return
		}

	} else {
		fmt.Println("Error: tcp protocol must be provided.")
		return
	}

	srcnspod := args[0]
	destnssvc := args[1]
	var src_pod_hostnetwork bool
	var dst_pod_hostnetwork bool
	var src_ep EndPoints
	var dest_ep EndPoints
	var destPodIp string
	var destPod *v1.Pod
	var destNodeName string
	var dst_opflex_pod string
	var destOvsPodName string
	var request_egress_packetdropped bool
	var reply_egress_packetdropped bool
	var tun_id string
	var tun_id_int int64
	var targetPort int32
	var request_ingress_packetdropped bool
	var reply_ingress_packetdropped bool

	srcns, srcpodname, err := splitNamespaceAndPod(srcnspod)
	if err != nil {
		fmt.Println(err)
		return
	}

	destns, destsvcname, err := splitNamespaceAndPod(destnssvc)
	if err != nil {
		fmt.Println(err)
		return
	}

	kubeClient := initClientPrintError()
	if kubeClient == nil {
		return
	}

	is_src_ns_valid := validNamespace(kubeClient, srcns)
	if !is_src_ns_valid {
		fmt.Fprintf(os.Stderr, "Could not find namespace: %s\n", srcns)
		return
	}

	is_dest_ns_valid := validNamespace(kubeClient, destns)
	if !is_dest_ns_valid {
		fmt.Fprintf(os.Stderr, "Could not find namespace: %s\n", destns)
		return
	}

	srcPod, err := getPod(kubeClient, srcns, srcpodname)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not find source pod:", err)
		return
	}

	dest_svc, err := getSvc(kubeClient, destns, destsvcname)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not find destination service:", err)
		return
	}

	for _, port := range dest_svc.Spec.Ports {
		if port.Port == int32(tcpDst) {
			if port.TargetPort.Type == intstr.Int {
				targetPort = port.TargetPort.IntVal
			}
		}
	}

	if targetPort == 0 {
		fmt.Fprintln(os.Stderr, "tcpDst port does not match with service port")
		return
	}

	srcOvsPodName, err := podForNode(kubeClient, "aci-containers-system",
		srcPod.Spec.NodeName, "name=aci-containers-openvswitch")

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	src_opflex_pod, err := podForNode(kubeClient, "aci-containers-system",
		srcPod.Spec.NodeName, "name=aci-containers-host")

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	src_node, err := kubeClient.CoreV1().Nodes().Get(kubecontext.TODO(), srcPod.Spec.NodeName, metav1.GetOptions{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not find source node:", err)
		return
	}

	if podIPMatchesNodeIP(srcPod.Status.PodIP, src_node.Status.Addresses) {
		src_pod_hostnetwork = true
	}

	if !src_pod_hostnetwork {
		src_ep, err = findEpFile(srcPod, src_opflex_pod)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}

	dest_svc_file, err := findServiceFile(kubeClient, srcPod, dest_svc.Spec.ClusterIP)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	if _, ok := nodeIdMaps.nodeMaps[srcPod.Spec.NodeName]; !ok {
		err := buildIdMaps(srcPod.Spec.NodeName, src_opflex_pod)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}

	fmt.Printf("\n\n%s%s%s", ColorGreen, "\nSummary\n", ColorReset)

	printACIDiagram()

	if !src_pod_hostnetwork {
		// Print the EP details
		printEndpointDetails(src_ep, srcPod, src_opflex_pod)
	}

	// Print the EP details
	printServiceDetails(dest_svc_file)

	//Source Calculation
	src_buffer := new(bytes.Buffer)

	cmd_args := []string{}
	request_out_bridgeflows := []Bridge{}

	if !src_pod_hostnetwork {

		cmd_args = []string{"exec", "-n", "aci-containers-system", srcOvsPodName,
			"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-access 'in_port=%s, tcp, nw_ttl=10, nw_src=%s, nw_dst=%s, dl_src=%s, tcp_src=%d,tcp_dst=%d'", src_ep.Attributes.InterfaceName,
				srcPod.Status.PodIP, dest_svc_file.ServiceMapping[0].ServiceIp, src_ep.Mac, tcpSrc, tcpDst)}

		err = execKubectl(cmd_args, src_buffer)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}

		sections := strings.Split(src_buffer.String(), "bridge")

		for idx, section := range sections {
			if strings.Contains(section, "br-access") {
				request_out_bridgeflows = append(request_out_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" + section, nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
			} else if strings.Contains(section, "br-int") {
				request_out_bridgeflows = append(request_out_bridgeflows, Bridge{br_type: "br-int", brFlows: "bridge" + section, nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
			}

			if idx > 0 && strings.Contains(sections[idx-1], "br-access") && strings.Contains(sections[idx-1], "resume conntrack") {
				request_out_bridgeflows[len(request_out_bridgeflows)-1].br_type = "br-access"
			}

			if idx > 0 && strings.Contains(sections[idx-1], "br-int") && strings.Contains(sections[idx-1], "resume conntrack") {
				request_out_bridgeflows[len(request_out_bridgeflows)-1].br_type = "br-int"
			}
		}

		for idx, _ := range request_out_bridgeflows {
			request_out_bridgeflows[idx].brFlowEntries = request_out_bridgeflows[idx].parseFlowEntries()
			request_out_bridgeflows[idx].out_br_buff = request_out_bridgeflows[idx].buildPacketTrace()
		}

		for _, br := range request_out_bridgeflows {
			if br.summary != nil && br.summary.PacketDropped {
				if br.br_type == "br-access" {
					fmt.Printf("\n%s%s%s\n", ColorGreen, "ForwardPath Summary", ColorReset)
					fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n\n", ColorRed, "br-access", br.summary.previousTable, brAccessTableDescriptions[br.summary.previousTable], srcPod.Spec.NodeName, ColorReset)
					request_egress_packetdropped = true
				} else {
					fmt.Printf("\n%s%s%s\n", ColorGreen, "ForwardPath Summary", ColorReset)
					fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n\n", ColorRed, "br-int", br.summary.previousTable, brIntTableDescriptions[br.summary.previousTable], srcPod.Spec.NodeName, ColorReset)
					request_egress_packetdropped = true
				}
			}

			if br.summary != nil && br.br_type == "br-int" && br.summary.ip_dst != "" {
				destPodIp = br.summary.ip_dst
			}
		}

		if !request_egress_packetdropped {
			if destPodIp != "" {
				destPod, err = findEndpoint(kubeClient, destPodIp, tcpDst, dest_svc)
				if err != nil {
					fmt.Printf("%sEndpoint is a node with IP:%s%s\n", ColorGreen, destPodIp, ColorReset)
					destNodeName, err = findNodeByIP(kubeClient, destPodIp)
					if err != nil {
						fmt.Fprintln(os.Stderr, "Error: ", err)
						return
					}
				}
			}

			if destPod != nil {
				dst_node, err := kubeClient.CoreV1().Nodes().Get(kubecontext.TODO(), destPod.Spec.NodeName, metav1.GetOptions{})
				if err != nil {
					fmt.Fprintln(os.Stderr, "Could not find destination node:", err)
					return
				}

				if podIPMatchesNodeIP(destPod.Status.PodIP, dst_node.Status.Addresses) {
					dst_pod_hostnetwork = true
				}

				dst_opflex_pod, err = podForNode(kubeClient, "aci-containers-system",
					destPod.Spec.NodeName, "name=aci-containers-host")

				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					return
				}

				destOvsPodName = ""
				if destPod.Spec.NodeName != srcPod.Spec.NodeName {
					destOvsPodName, err = podForNode(kubeClient, "aci-containers-system",
						destPod.Spec.NodeName, "name=aci-containers-openvswitch")

					if err != nil {
						fmt.Fprintln(os.Stderr, err)
						return
					}
				} else {
					destOvsPodName = srcOvsPodName
				}

				if !dst_pod_hostnetwork {
					dest_ep, err = findEpFile(destPod, dst_opflex_pod)
					if err != nil {
						fmt.Fprintln(os.Stderr, err)
						return

					}

					printEndpointDetails(dest_ep, destPod, dst_opflex_pod)

					//Find gbpObjects
					gbpObjects, err := findGbpPolicy(kubeClient, destPod)
					if err != nil {
						fmt.Fprintln(os.Stderr, err)
						return
					}

					//Destination Calculation
					tun_id, err = findTunnelId(gbpObjects, dest_ep)
					if err != nil {
						fmt.Fprintln(os.Stderr, err)
						return
					}

					tun_id_int, _ = strconv.ParseInt("0x"+tun_id, 0, 64)

					if srcPod.Spec.NodeName != destPod.Spec.NodeName {
						fmt.Printf("\n%s%s%s\n", ColorGreen, "ForwardPath Summary", ColorReset)
						fmt.Printf("%s=> Packet sent out from node:%s with source_epg %s(%s) to destination service ip %s which translates to endpoint %s(IP->%s) with destination_epg/VXLAN_Tunnel_ID:0x%s(decimal:%d)(%s) %s\n\n",
							ColorGreen, srcPod.Spec.NodeName, request_out_bridgeflows[len(request_out_bridgeflows)-1].summary.TunnelID, src_ep.EndpointGroupName, dest_svc.Spec.ClusterIP, destPod.Name, destPod.Status.PodIP, tun_id, tun_id_int, dest_ep.EndpointGroupName, ColorReset)

					} else {
						fmt.Printf("\n%s%s%s\n", ColorGreen, "ForwardPath Summary", ColorReset)
						fmt.Printf("%s=> Packet sent out to destination service ip %s which translates to endpoint %s(IP->%s) and recieved on same node: %s %s\n\n", ColorGreen, dest_svc.Spec.ClusterIP, destPod.Name, destPod.Status.PodIP, srcPod.Spec.NodeName, ColorReset)
					}
				} else {
					if srcPod.Spec.NodeName != destPod.Spec.NodeName {
						fmt.Printf("\n%s%s%s\n", ColorGreen, "ForwardPath Summary", ColorReset)
						fmt.Printf("%s=> Packet sent out from node:%s with source_epg %s(%s) to destination service ip %s with endpoint IP:%s on node(%s) network%s\n\n",
							ColorGreen, srcPod.Spec.NodeName, request_out_bridgeflows[len(request_out_bridgeflows)-1].summary.TunnelID, src_ep.EndpointGroupName, dest_svc.Spec.ClusterIP, destPod.Status.PodIP, dst_node.Name, ColorReset)

					} else {
						fmt.Printf("\n%s%s%s\n", ColorGreen, "ForwardPath Summary", ColorReset)
						fmt.Printf("%s=> Packet sent out to destination service ip %s which translates to endpoint %s(IP->%s) and recieved on same node: %s %s\n\n", ColorGreen, dest_svc.Spec.ClusterIP, destPod.Name, destPod.Status.PodIP, srcPod.Spec.NodeName, ColorReset)
					}
				}

			} else {
				fmt.Printf("\n%s%s%s\n", ColorGreen, "ForwardPath Summary", ColorReset)
				fmt.Printf("%s=> Packet sent out from node:%s with source_epg %s(%s) to destination service ip %s with endpoint IP:%s on node network%s\n\n",
					ColorGreen, srcPod.Spec.NodeName, request_out_bridgeflows[len(request_out_bridgeflows)-1].summary.TunnelID, src_ep.EndpointGroupName, dest_svc.Spec.ClusterIP, destPodIp, ColorReset)
			}

		}

	} else {
		fmt.Printf("\n%s%s%s\n", ColorGreen, "ForwardPath Summary", ColorReset)
		fmt.Printf("%s=> Packet sent out from pod(%s) on node(%s) network with IP:%s to destination service ip:%s%s\n\n",
			ColorGreen, srcpodname, srcPod.Spec.NodeName, srcPod.Status.PodIP, dest_svc.Spec.ClusterIP, ColorReset)
	}

	request_in_bridgeflows := []Bridge{}
	dest_buffer := new(bytes.Buffer)
	if !request_egress_packetdropped {
		if destPod != nil {
			if _, ok := nodeIdMaps.nodeMaps[destPod.Spec.NodeName]; !ok {
				err := buildIdMaps(destPod.Spec.NodeName, dst_opflex_pod)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					return
				}
			}

			if !dst_pod_hostnetwork && destPod.Spec.NodeName != srcPod.Spec.NodeName {

				cmd_args = []string{"exec", "-n", "aci-containers-system", destOvsPodName,
					"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-int 'in_port=vxlan0,tun_id=0x%s, tcp,nw_ttl=10, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s,tcp_src=%d,tcp_dst=%d'",
						tun_id, srcPod.Status.PodIP, destPod.Status.PodIP, "00:22:bd:f8:19:ff", dest_ep.Mac, tcpSrc, targetPort)}

				err = execKubectl(cmd_args, dest_buffer)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					return
				}

				sections := strings.Split(dest_buffer.String(), "bridge")

				for idx, section := range sections {
					if strings.Contains(section, "br-access") {
						request_in_bridgeflows = append(request_in_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" + section, nodename: destPod.Spec.NodeName, ovsPod: destOvsPodName, opflexPod: dst_opflex_pod})
					} else if strings.Contains(section, "br-int") {
						request_in_bridgeflows = append(request_in_bridgeflows, Bridge{br_type: "br-int", brFlows: "bridge" + section, nodename: destPod.Spec.NodeName, ovsPod: destOvsPodName, opflexPod: dst_opflex_pod})
					}

					if idx > 0 && strings.Contains(sections[idx-1], "br-access") && strings.Contains(sections[idx-1], "resume conntrack") {
						request_in_bridgeflows[len(request_in_bridgeflows)-1].br_type = "br-access"
					}

					if idx > 0 && strings.Contains(sections[idx-1], "br-int") && strings.Contains(sections[idx-1], "resume conntrack") {
						request_in_bridgeflows[len(request_in_bridgeflows)-1].br_type = "br-int"
					}
				}

				for idx, _ := range request_in_bridgeflows {
					request_in_bridgeflows[idx].brFlowEntries = request_in_bridgeflows[idx].parseFlowEntries()
					request_in_bridgeflows[idx].out_br_buff = request_in_bridgeflows[idx].buildPacketTrace()
				}

				for _, br := range request_in_bridgeflows {
					if br.summary != nil && br.summary.PacketDropped {
						if br.br_type == "br-int" {
							fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n\n", ColorRed, "br-int", br.summary.previousTable, brIntTableDescriptions[br.summary.previousTable], destPod.Spec.NodeName, ColorReset)
							request_ingress_packetdropped = true

						} else {
							fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n\n", ColorRed, "br-access", br.summary.previousTable, brAccessTableDescriptions[br.summary.previousTable], destPod.Spec.NodeName, ColorReset)
							request_ingress_packetdropped = true
						}
					}
				}

				if !request_ingress_packetdropped {
					fmt.Printf("%s=> Packet recieved on the destination %s %s\n", ColorGreen, destPod.Status.PodIP, ColorReset)
				}

			} else {
				if srcPod.Spec.NodeName != destPod.Spec.NodeName {
					if !src_pod_hostnetwork {
						fmt.Printf(
							"%s=> No explicit ovs-rules found for the request packet at the destination\n"+
								"The packet sent out from node:%s with source_epg %s\n"+
								"to destination pod IP (%s) on the node(%s) network %s\n\n",
							ColorGreen,
							srcPod.Spec.NodeName,
							src_ep.EndpointGroupName,
							destPod.Status.PodIP,
							destPod.Spec.NodeName,
							ColorReset,
						)

					} else {
						fmt.Printf(
							"%s=> No explicit ovs-rules found for the request packet at the destination\n"+
								"The packet sent out from node:%s to destination pod IP (%s) on the node(%s) network %s\n\n",
							ColorGreen,
							srcPod.Spec.NodeName,
							destPod.Status.PodIP,
							destPod.Spec.NodeName,
							ColorReset,
						)

					}

				}
			}
		} else {
			fmt.Printf(
				"%s=> No explicit ovs-rules found for the request packet at the destination\n"+
					"The packet sent out from node:%s to one of the service endpoints %s\n\n",
				ColorGreen,
				srcPod.Spec.NodeName,
				ColorReset,
			)

		}

	}

	/// Reply Path ///////////////////

	reply_out_bridgeflows := []Bridge{}
	src_buffer = new(bytes.Buffer)
	if !request_egress_packetdropped && !request_ingress_packetdropped {
		fmt.Printf("\n\n%s%s%s\n\n", ColorGreen, "ReturnPath Summary", ColorReset)
		if !src_pod_hostnetwork {
			gbpObjects, err := findGbpPolicy(kubeClient, srcPod)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}

			tun_id, err = findTunnelId(gbpObjects, src_ep)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}

			tun_id_int, _ = strconv.ParseInt("0x"+tun_id, 0, 64)
		}

		if !dst_pod_hostnetwork && destPod != nil {
			if destPod.Spec.NodeName != srcPod.Spec.NodeName {
				cmd_args = []string{"exec", "-n", "aci-containers-system", destOvsPodName,
					"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-access 'in_port=%s, tcp, nw_ttl=10,nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s,tcp_src=%d,tcp_dst=%d'", dest_ep.Attributes.InterfaceName,
						destPod.Status.PodIP, srcPod.Status.PodIP, dest_ep.Mac, "00:22:bd:f8:19:ff", targetPort, tcpSrc)}

				err = execKubectl(cmd_args, src_buffer)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					return

				}

				sections := strings.Split(src_buffer.String(), "bridge")

				for idx, section := range sections {
					if strings.Contains(section, "br-access") {
						reply_out_bridgeflows = append(reply_out_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" + section, nodename: destPod.Spec.NodeName, ovsPod: destOvsPodName, opflexPod: dst_opflex_pod})
					} else if strings.Contains(section, "br-int") {
						reply_out_bridgeflows = append(reply_out_bridgeflows, Bridge{br_type: "br-int", brFlows: "bridge" + section, nodename: destPod.Spec.NodeName, ovsPod: destOvsPodName, opflexPod: dst_opflex_pod})
					}

					if idx > 0 && strings.Contains(sections[idx-1], "br-access") && strings.Contains(sections[idx-1], "resume conntrack") {
						reply_out_bridgeflows[len(reply_out_bridgeflows)-1].br_type = "br-access"
					}

					if idx > 0 && strings.Contains(sections[idx-1], "br-int") && strings.Contains(sections[idx-1], "resume conntrack") {
						reply_out_bridgeflows[len(reply_out_bridgeflows)-1].br_type = "br-int"
					}
				}

				for idx, _ := range reply_out_bridgeflows {
					reply_out_bridgeflows[idx].brFlowEntries = reply_out_bridgeflows[idx].parseFlowEntries()
					reply_out_bridgeflows[idx].out_br_buff = reply_out_bridgeflows[idx].buildPacketTrace()
				}

				for _, br := range reply_out_bridgeflows {
					if br.summary != nil && br.summary.PacketDropped {
						if br.br_type == "br-access" {
							fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n\n", ColorRed, "br-access", br.summary.previousTable, brAccessTableDescriptions[br.summary.previousTable], destPod.Spec.NodeName, ColorReset)
							reply_egress_packetdropped = true
						} else {
							fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n\n", ColorRed, "br-int", br.summary.previousTable, brIntTableDescriptions[br.summary.previousTable], destPod.Spec.NodeName, ColorReset)
							reply_egress_packetdropped = true
						}
					}
				}

				if !reply_egress_packetdropped {
					if !src_pod_hostnetwork {
						fmt.Printf("%s=> Packet sent out from node:%s with epg %s(%s) to origin pod ip %s with destination_epg/VXLAN_Tunnel_ID:0x%s(decimal:%d)(%s) %s\n\n",
							ColorGreen, destPod.Spec.NodeName, reply_out_bridgeflows[len(request_out_bridgeflows)-1].summary.TunnelID, dest_ep.EndpointGroupName, srcPod.Status.PodIP, tun_id, tun_id_int, src_ep.EndpointGroupName, ColorReset)
					} else {
						fmt.Printf("%s=> Packet sent out from node:%s with epg %s(%s) to origin pod ip %s on node(%s) network %s\n\n",
							ColorGreen, destPod.Spec.NodeName, reply_out_bridgeflows[len(request_out_bridgeflows)-1].summary.TunnelID, dest_ep.EndpointGroupName, srcPod.Status.PodIP, src_node.Name, ColorReset)
					}
				}
			}
		} else {
			if !src_pod_hostnetwork {
				fmt.Printf(
					"%s=> No explicit ovs-rules found for the reply packet\n"+
						"from destination pod IP %s on node network to source pod IP %s\n"+
						"with destination_epg/VXLAN_Tunnel_ID:0x%s(decimal:%d)(%s) %s\n\n",
					ColorGreen,
					destPodIp,
					srcPod.Status.PodIP,
					tun_id,
					tun_id_int,
					src_ep.EndpointGroupName,
					ColorReset,
				)

			} else {
				fmt.Printf(
					"%s=> No explicit ovs-rules found for the reply packet\n"+
						"on the node %s %s\n\n",
					ColorGreen,
					srcPod.Spec.NodeName,
					ColorReset,
				)

			}

		}
	}

	reply_in_bridgeflows := []Bridge{}
	dest_buffer = new(bytes.Buffer)
	if !request_egress_packetdropped && !request_ingress_packetdropped && !reply_egress_packetdropped {
		if !src_pod_hostnetwork {
			if destPod != nil {
				if destPod.Spec.NodeName != srcPod.Spec.NodeName {
					cmd_args = []string{"exec", "-n", "aci-containers-system", srcOvsPodName,
						"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-int 'in_port=vxlan0,tun_id=0x%s, tcp,ct_state=trk|est,ct_mark=%s,nw_src=%s, nw_dst=%s,dl_dst=%s,tcp_src=%d,nw_ttl=64'",
							tun_id, ct_mark, destPod.Status.PodIP, srcPod.Status.PodIP, src_ep.Mac, targetPort)}

					err = execKubectl(cmd_args, dest_buffer)
					if err != nil {
						fmt.Fprintln(os.Stderr, err)
						return

					}
				}

			} else {
				cmd_args = []string{"exec", "-n", "aci-containers-system", srcOvsPodName,
					"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-int 'in_port=vxlan0,tun_id=0x%s, tcp,ct_state=trk|est,ct_mark=%s,nw_src=%s, nw_dst=%s,dl_dst=%s,tcp_src=%d,nw_ttl=64'",
						tun_id, ct_mark, destPodIp, srcPod.Status.PodIP, src_ep.Mac, targetPort)}

				err = execKubectl(cmd_args, dest_buffer)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					return

				}

			}

			sections := strings.Split(dest_buffer.String(), "bridge")

			for idx, section := range sections {
				if strings.Contains(section, "br-access") {
					reply_in_bridgeflows = append(reply_in_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" + section, nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
				} else if strings.Contains(section, "br-int") {
					reply_in_bridgeflows = append(reply_in_bridgeflows, Bridge{br_type: "br-int", brFlows: "bridge" + section, nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
				}

				if idx > 0 && strings.Contains(sections[idx-1], "br-access") && strings.Contains(sections[idx-1], "resume conntrack") {
					reply_in_bridgeflows[len(reply_in_bridgeflows)-1].br_type = "br-access"
				}

				if idx > 0 && strings.Contains(sections[idx-1], "br-int") && strings.Contains(sections[idx-1], "resume conntrack") {
					reply_in_bridgeflows[len(reply_in_bridgeflows)-1].br_type = "br-int"
				}

			}

			for idx, _ := range reply_in_bridgeflows {
				reply_in_bridgeflows[idx].brFlowEntries = reply_in_bridgeflows[idx].parseFlowEntries()
				reply_in_bridgeflows[idx].out_br_buff = reply_in_bridgeflows[idx].buildPacketTrace()
			}

			for _, br := range reply_in_bridgeflows {
				if br.summary != nil && br.summary.PacketDropped {
					if br.br_type == "br-access" {
						fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n\n", ColorRed, "br-access", br.summary.previousTable, brAccessTableDescriptions[br.summary.previousTable], srcPod.Spec.NodeName, ColorReset)
						reply_ingress_packetdropped = true
					} else {
						fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n\n", ColorRed, "br-int", br.summary.previousTable, brIntTableDescriptions[br.summary.previousTable], srcPod.Spec.NodeName, ColorReset)
						reply_ingress_packetdropped = true
					}
				}
			}

			if !reply_ingress_packetdropped {
				fmt.Printf("%s=> Packet recieved on the source Pod %s(%s) %s\n\n", ColorGreen, srcPod.Name, srcPod.Status.PodIP, ColorReset)
			}
		}
	}

	if verbose {
		//fmt.Printf("\n\n%s%s%s\n", ColorGreen, "Detailed Explanation", ColorReset)
		if !src_pod_hostnetwork {
			fmt.Printf("\n\n%s%s%s%s\n", ColorGreen, "ForwardPath Outgoing Packet from node: ", src_node.Name, ColorReset)
			for _, br := range request_out_bridgeflows {
				if br.br_type == "br-access" {
					fmt.Printf("\n%s%s%s\n", ColorYellow, "br-access:", ColorReset)
					fmt.Println(br.out_br_buff)
				} else {
					fmt.Printf("\n%s%s%s\n", ColorYellow, "br-int:", ColorReset)
					fmt.Println(br.out_br_buff)
				}

			}
		}

		if !dst_pod_hostnetwork && !request_egress_packetdropped && destPod != nil && srcPod.Spec.NodeName != destPod.Spec.NodeName {
			fmt.Printf("\n\n%s%s%s%s\n", ColorGreen, "ForwardPath Incoming Packet to node: ", destPod.Spec.NodeName, ColorReset)
			for _, br := range request_in_bridgeflows {
				if br.br_type == "br-access" {
					fmt.Printf("\n%s%s%s\n", ColorYellow, "br-access:", ColorReset)
					fmt.Println(br.out_br_buff)
				} else {
					fmt.Printf("\n%s%s%s\n", ColorYellow, "br-int:", ColorReset)
					fmt.Println(br.out_br_buff)
				}
			}
		}

		if !dst_pod_hostnetwork && !request_egress_packetdropped && !request_ingress_packetdropped && destPod != nil && srcPod.Spec.NodeName != destPod.Spec.NodeName {
			fmt.Printf("\n\n%s%s%s%s\n", ColorGreen, "ReturnPath Outgoing Packet from node: ", destPod.Spec.NodeName, ColorReset)
			for _, br := range reply_out_bridgeflows {
				if br.br_type == "br-access" {
					fmt.Printf("\n%s%s%s\n", ColorYellow, "br-access:", ColorReset)
					fmt.Println(br.out_br_buff)
				} else {
					fmt.Printf("\n%s%s%s\n", ColorYellow, "br-int:", ColorReset)
					fmt.Println(br.out_br_buff)
				}
			}
		}

		if !src_pod_hostnetwork && !request_egress_packetdropped && !request_ingress_packetdropped && !reply_egress_packetdropped && ((destPod != nil && srcPod.Spec.NodeName != destPod.Spec.NodeName) || (destPodIp != "" && destNodeName != "" && src_node.Name != destNodeName)) {
			fmt.Printf("\n\n%s%s%s%s\n", ColorGreen, "ReturnPath Incoming Packet to node: ", src_node.Name, ColorReset)
			for _, br := range reply_in_bridgeflows {
				if br.br_type == "br-access" {
					fmt.Printf("\n%s%s%s\n", ColorYellow, "br-access:", ColorReset)
					fmt.Println(br.out_br_buff)
				} else {
					fmt.Printf("\n%s%s%s\n", ColorYellow, "br-int:", ColorReset)
					fmt.Println(br.out_br_buff)
				}
			}
		}
	}
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func pod_to_ext_tracepacket(args []string, tcpFlag bool, tcpSrc int, tcpDst int, verbose bool) {
	if tcpFlag {
		if tcpSrc == 0 && tcpDst == 0 {
			fmt.Println("Error: If tcp is specified, either tcp_src or tcp_dst must be provided.")
			return
		} else if tcpSrc == 0 {
			tcpSrc = 12345
		}
	} else {
		fmt.Println("Error: tcp protocol must be provided.")
		return
	}

	if !isValidPort(tcpSrc) {
		fmt.Println("Error: Please enter tcpSrc value in valid port range [1-65535].")
		return
	}

	if !isValidPort(tcpDst) {
		fmt.Println("Error: Please enter tcpDst value in valid port range [1-65535].")
		return
	}

	srcnspod := args[0]
	destip := args[1]
	var src_pod_hostnetwork bool

	if !isValidIP(destip) {
		fmt.Printf("%s is a not valid IP address.\n", destip)
		return
	}

	srcns, srcpodname, err := splitNamespaceAndPod(srcnspod)
	if err != nil {
		fmt.Println(err)
		return
	}

	kubeClient := initClientPrintError()
	if kubeClient == nil {
		return
	}

	is_src_ns_valid := validNamespace(kubeClient, srcns)
	if !is_src_ns_valid {
		fmt.Fprintf(os.Stderr, "Could not find namespace: %s\n", srcns)
		return
	}

	srcPod, err := getPod(kubeClient, srcns, srcpodname)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not find source pod:", err)
		return
	}

	src_node, err := kubeClient.CoreV1().Nodes().Get(kubecontext.TODO(), srcPod.Spec.NodeName, metav1.GetOptions{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not find source node:", err)
		return
	}

	if podIPMatchesNodeIP(srcPod.Status.PodIP, src_node.Status.Addresses) {
		src_pod_hostnetwork = true
	}

	if src_pod_hostnetwork {
		fmt.Fprintf(os.Stderr, "\n%sCould not track OVS datapath as pod(%s) is on the node(%s) network(%s)%s\n", ColorYellow, srcPod.Name, src_node.Name, srcPod.Status.PodIP, ColorReset)
		return
	}

	srcOvsPodName, err := podForNode(kubeClient, "aci-containers-system",
		srcPod.Spec.NodeName, "name=aci-containers-openvswitch")

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	src_opflex_pod, err := podForNode(kubeClient, "aci-containers-system",
		srcPod.Spec.NodeName, "name=aci-containers-host")

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	src_ep, err := findEpFile(srcPod, src_opflex_pod)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return

	}

	if _, ok := nodeIdMaps.nodeMaps[srcPod.Spec.NodeName]; !ok {
		err := buildIdMaps(srcPod.Spec.NodeName, src_opflex_pod)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}

	//Source Calculation
	src_buffer := new(bytes.Buffer)

	cmd_args := []string{}

	cmd_args = []string{"exec", "-n", "aci-containers-system", srcOvsPodName,
		"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-access 'in_port=%s, tcp, nw_ttl=10, nw_src=%s, nw_dst=%s, dl_src=%s, tcp_src=%d,tcp_dst=%d'", src_ep.Attributes.InterfaceName,
			srcPod.Status.PodIP, destip, src_ep.Mac, tcpSrc, tcpDst)}

	err = execKubectl(cmd_args, src_buffer)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	// Split the buffer into sections
	sections := strings.Split(src_buffer.String(), "bridge")

	out_bridgeflows := []Bridge{}

	for idx, section := range sections {
		if strings.Contains(section, "br-access") {
			out_bridgeflows = append(out_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" + section, nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
		} else if strings.Contains(section, "br-int") {
			out_bridgeflows = append(out_bridgeflows, Bridge{br_type: "br-int", brFlows: "bridge" + section, nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
		}

		if idx > 0 && strings.Contains(sections[idx-1], "br-access") && strings.Contains(sections[idx-1], "resume conntrack") {
			out_bridgeflows[len(out_bridgeflows)-1].br_type = "br-access"
		}

		if idx > 0 && strings.Contains(sections[idx-1], "br-int") && strings.Contains(sections[idx-1], "resume conntrack") {
			out_bridgeflows[len(out_bridgeflows)-1].br_type = "br-int"
		}
	}

	for idx, _ := range out_bridgeflows {
		out_bridgeflows[idx].brFlowEntries = out_bridgeflows[idx].parseFlowEntries()
		out_bridgeflows[idx].out_br_buff = out_bridgeflows[idx].buildPacketTrace()
	}

	var packetDropped bool

	fmt.Printf("\n\n%s%s%s", ColorGreen, "\nSummary\n", ColorReset)

	printACIDiagram()

	// Print the EP details
	printEndpointDetails(src_ep, srcPod, src_opflex_pod)

	for _, br := range out_bridgeflows {
		if br.summary != nil && br.summary.PacketDropped {
			if br.br_type == "br-access" {
				fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n", ColorRed, "br-access", br.summary.previousTable, brAccessTableDescriptions[br.summary.previousTable], srcPod.Spec.NodeName, ColorReset)
				packetDropped = true
			} else {
				fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n", ColorRed, "br-int", br.summary.previousTable, brIntTableDescriptions[br.summary.previousTable], srcPod.Spec.NodeName, ColorReset)
				packetDropped = true
			}
		}

	}

	if !packetDropped {
		if out_bridgeflows[len(out_bridgeflows)-1].summary.snat_ip != "" {
			fmt.Printf("%s=> Packet sent out from node:%s with source_epg %s(%s) with snat_ip %s to the destination %s:%d %s\n",
				ColorGreen, srcPod.Spec.NodeName, out_bridgeflows[len(out_bridgeflows)-1].summary.TunnelID, src_ep.EndpointGroupName, out_bridgeflows[len(out_bridgeflows)-1].summary.snat_ip, destip, tcpDst, ColorReset)
		} else {
			fmt.Printf("%s=> Packet sent out from node:%s with source_epg %s(%s) to the destination %s:%d %s\n",
				ColorGreen, srcPod.Spec.NodeName, out_bridgeflows[len(out_bridgeflows)-1].summary.TunnelID, src_ep.EndpointGroupName, destip, tcpDst, ColorReset)
		}

	}

	if verbose {
		//fmt.Printf("\n\n%s%s%s\n", ColorGreen, "Detailed Explanation", ColorReset)
		fmt.Printf("\n\n%s%s%s%s\n", ColorGreen, "Outgoing Packet from node: ", src_node.Name, ColorReset)
		for _, br := range out_bridgeflows {
			if br.br_type == "br-access" {
				fmt.Printf("\n%s%s%s\n", ColorYellow, "br-access:", ColorReset)
				fmt.Println(br.out_br_buff)
			} else {
				fmt.Printf("\n%s%s%s\n", ColorYellow, "br-int:", ColorReset)
				fmt.Println(br.out_br_buff)
			}

		}

	}

}

// FetchFileContent fetches the content of the file from the pod
func FetchFileContent(opflex_pod_name, filePath string) ([]byte, error) {
	file_buffer := new(bytes.Buffer)
	cmd_args := []string{"exec", "-n", "aci-containers-system", opflex_pod_name, "-c", "opflex-agent",
		"--", "/bin/sh", "-c", fmt.Sprintf("cat %s", filePath)}

	err := execKubectl(cmd_args, file_buffer)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return []byte{}, err
	}

	return file_buffer.Bytes(), nil
}

func buildIdMaps(nodename, opflex_pod_name string) error {
	for mapName, filePath := range idMapFiles {
		data, err := FetchFileContent(opflex_pod_name, filePath)
		if err != nil {
			return err
		}

		idMap := NewIdMap(data)
		//idMap.PrintID2StrMap()
		nodeIdMaps.AddIdMap(nodename, mapName, idMap)
	}
	return nil
}

func encodePipe(input string) string {
	// encode '|' to %7C and convert '%7C' with '%7c'
	encoded := url.QueryEscape(input)
	return strings.ReplaceAll(encoded, "%7C", "%7c")
}

func findTunnelId(gbpObjects []GBPObject, ep EndPoints) (string, error) {
	uri := "/PolicyUniverse/PolicySpace/" + ep.EgPolicySpace + "/GbpEpGroup/" + encodePipe(ep.EndpointGroupName) + "/GbpeInstContext/"
	tunID := ""
	found := false

	for _, gbpObject := range gbpObjects {
		if gbpObject.URI == uri {
			found = true
			for _, element := range gbpObject.Properties {
				if element.Name == "encapId" {
					encapIDStr := fmt.Sprintf("%v", element.Data)
					encapIDFloat, err := strconv.ParseFloat(encapIDStr, 64)
					if err != nil {
						return "", fmt.Errorf("failed to convert encapId to float for URI: %s", uri)
					}
					encapID := int(encapIDFloat)
					tunID = fmt.Sprintf("%X", encapID)
					break
				}
			}
			break
		}
	}

	if !found {
		return "", fmt.Errorf("URI not found: %s", uri)
	}

	if tunID == "" {
		return "", errors.New("Could not find tunnel ID")
	}

	return tunID, nil
}

func findEpFile(pod *v1.Pod, hostPodName string) (EndPoints, error) {

	ep_buffer := new(bytes.Buffer)
	podIPRegex := fmt.Sprintf("\\b%s\\b", regexp.QuoteMeta(pod.Status.PodIP))
	cmd_args := []string{"exec", "-n", "aci-containers-system", hostPodName, "-c", "opflex-agent",
		"--", "/bin/sh", "-c", fmt.Sprintf("for file in $(grep -l '%s' /usr/local/var/lib/opflex-agent-ovs/endpoints/*); do cat $file; done", podIPRegex)}

	err := execKubectl(cmd_args, ep_buffer)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return EndPoints{}, err
	}

	if ep_buffer.Len() == 0 {
		return EndPoints{}, errors.New("no endpoints found")
	}

	//Convert ep_buffer to Endpoint
	var ep EndPoints

	// Unmarshal the JSON data from ep_buffer into the EndPoints struct
	err = json.Unmarshal(ep_buffer.Bytes(), &ep)
	if err != nil {
		fmt.Println("Error:", err)
		return EndPoints{}, err
	}

	return ep, nil
}

func findServiceFile(kubeClient kubernetes.Interface, pod *v1.Pod, svcip string) (Service, error) {
	hostPodName, err := podForNode(kubeClient, "aci-containers-system",
		pod.Spec.NodeName, "name=aci-containers-host")

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return Service{}, err
	}

	svc_buffer := new(bytes.Buffer)
	serviceRegex := fmt.Sprintf("\\b%s\\b", regexp.QuoteMeta(svcip))
	cmd_args := []string{
		"exec",
		"-n", "aci-containers-system",
		hostPodName,
		"-c", "opflex-agent",
		"--",
		"/bin/sh", "-c",
		fmt.Sprintf("for file in $(grep -l '%s' /usr/local/var/lib/opflex-agent-ovs/services/*); do cat $file; done", serviceRegex),
	}

	err = execKubectl(cmd_args, svc_buffer)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return Service{}, err
	}

	if svc_buffer.Len() == 0 {
		return Service{}, errors.New("no endpoints found")
	}

	//Convert ep_buffer to Endpoint
	var svc Service

	// Unmarshal the JSON data from ep_buffer into the EndPoints struct
	err = json.Unmarshal(svc_buffer.Bytes(), &svc)
	if err != nil {
		fmt.Println("Error:", err)
		return Service{}, err
	}

	return svc, nil
}

func printEndpointDetails(ep EndPoints, pod *v1.Pod, hostPodName string) {
	fmt.Printf("\n%sPod %s:", ColorYellow, pod.Name)
	fmt.Println(ColorReset)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "%sUUID:\t%s\n", ColorGreen, ep.Uuid)
	fmt.Fprintf(w, "%sEgPolicySpace:\t%s\n", ColorGreen, ep.EgPolicySpace)
	fmt.Fprintf(w, "%sEndpointGroupName:\t%s\n", ColorGreen, ep.EndpointGroupName)
	//fmt.Fprintf(w, "%sQoS Policy:\t%v\n", ColorGreen, ep.QosPolicy)
	fmt.Fprintf(w, "%sIP:\t%v\n", ColorGreen, ep.Ip)
	fmt.Fprintf(w, "%sMAC Address:\t%s\n", ColorGreen, ep.Mac)
	fmt.Fprintf(w, "%sAccess Interface:\t%s\n", ColorGreen, ep.AccessInterface)
	fmt.Fprintf(w, "%sAccess Uplink Interface:\t%s\n", ColorGreen, ep.AccessUplinkInterface)
	fmt.Fprintf(w, "%sInterface Name:\t%s\n", ColorGreen, ep.InterfaceName)
	fmt.Fprintf(w, "%sNamespace:\t%s\n", ColorGreen, ep.Attributes.Namespace)
	//fmt.Fprintf(w, "%sVM Name:\t%s\n", ColorGreen, ep.Attributes.VmName)
	fmt.Fprintf(w, "%sPod Name:\t%s\n", ColorGreen, pod.Name)
	fmt.Fprintf(w, "%sNode Name:\t%s\n", ColorGreen, pod.Spec.NodeName)
	w.Flush()

	fmt.Println(ColorReset)
}

func printServiceDetails(svc Service) {
	fmt.Printf("\n%sService %s%s:", ColorYellow, svc.Attributes.Name, ColorReset)
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "%sUUID:\t%s%s\n", ColorGreen, svc.Uuid, ColorReset)
	fmt.Fprintf(w, "%sDomain Policy Space:\t%s%s\n", ColorGreen, svc.DomainPolicySpace, ColorReset)
	fmt.Fprintf(w, "%sDomain Name:\t%s%s\n", ColorGreen, svc.DomainName, ColorReset)
	fmt.Fprintf(w, "%sService Mode:\t%s%s\n", ColorGreen, svc.ServiceMode, ColorReset)
	fmt.Fprintf(w, "%sService Type:\t%s%s\n", ColorGreen, svc.ServiceType, ColorReset)
	fmt.Fprintf(w, "%sAttributes Name:\t%s%s\n", ColorGreen, svc.Attributes.Name, ColorReset)
	fmt.Fprintf(w, "%sNamespace:\t%s%s\n", ColorGreen, svc.Attributes.Namespace, ColorReset)
	fmt.Fprintf(w, "%sService Name:\t%s%s\n", ColorGreen, svc.Attributes.ServiceName, ColorReset)

	for _, mapping := range svc.ServiceMapping {
		fmt.Fprintf(w, "%sService IP:\t%s%s\n", ColorGreen, mapping.ServiceIp, ColorReset)
		fmt.Fprintf(w, "%sService Protocol:\t%s%s\n", ColorGreen, mapping.ServiceProto, ColorReset)
		fmt.Fprintf(w, "%sService Port:\t%d%s\n", ColorGreen, mapping.ServicePort, ColorReset)
		fmt.Fprintf(w, "%sNext Hop IPs:\t%v%s\n", ColorGreen, mapping.NextHopIps, ColorReset)
		fmt.Fprintf(w, "%sNext Hop Port:\t%d%s\n", ColorGreen, mapping.NextHopPort, ColorReset)
		fmt.Fprintf(w, "%sConntrack Enabled:\t%v%s\n", ColorGreen, mapping.ConntrackEnabled, ColorReset)
		fmt.Fprintf(w, "%sNode Port:\t%d%s\n", ColorGreen, mapping.NodePort, ColorReset)
		fmt.Fprintf(w, "%sSession Affinity Timeout Seconds:\t%d%s\n", ColorGreen, mapping.SessionAffinity.ClientIp.TimeoutSeconds, ColorReset)
	}

	w.Flush()
	fmt.Println()
}

func findGbpPolicy(kubeClient kubernetes.Interface, pod *v1.Pod) ([]GBPObject, error) {

	hostPodName, err := podForNode(kubeClient, "aci-containers-system", pod.Spec.NodeName, "name=aci-containers-host")
	if err != nil {
		return nil, fmt.Errorf("failed to find host pod: %w", err)
	}

	gbpBuffer := new(bytes.Buffer)
	cmdArgs := []string{"exec", "-n", "aci-containers-system", hostPodName, "-c", "opflex-agent", "--", "/bin/sh", "-c", "gbp_inspect -fprq DmtreeRoot -t dump"}

	err = execKubectl(cmdArgs, gbpBuffer)
	if err != nil {
		return nil, fmt.Errorf("failed to execute kubectl command: %w", err)
	}

	if gbpBuffer.Len() == 0 {
		return nil, errors.New("no policy found")
	}

	var gbpObjects []GBPObject
	err = json.Unmarshal(gbpBuffer.Bytes(), &gbpObjects)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal gbp_buffer: %w", err)
	}

	return gbpObjects, nil
}

// splitNamespaceAndPod splits the argument into namespace and pod
func splitNamespaceAndPod(arg string) (namespace, pod string, err error) {
	parts := strings.Split(arg, ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid format: %s, expected ns:pod", arg)
	}
	return parts[0], parts[1], nil
}

func printACIDiagram() {
	green := "\033[32m"
	reset := "\033[0m"
	fmt.Println()
	fmt.Println(green + `+------------------+              +------------------+`)
	fmt.Println(`|       pod        |              |       pod        |`)
	fmt.Println(`+------------------+              +------------------+`)
	fmt.Println(`          |                               |`)
	fmt.Println(green + `+------------------+              +------------------+`)
	fmt.Println(`|       veth       |              |       veth       |`)
	fmt.Println(`+------------------+              +------------------+`)
	fmt.Println(`          |                               |`)
	fmt.Println(green + `+------------------+              +------------------+`)
	fmt.Println(`|     br-access    |              |     br-access    |`)
	fmt.Println(`+------------------+              +------------------+`)
	fmt.Println(`          |                               |`)
	fmt.Println(green + `+------------------+              +------------------+`)
	fmt.Println(`|     pa-veth      |              |     pa-veth      |`)
	fmt.Println(`+------------------+              +------------------+`)
	fmt.Println(`          |                               |`)
	fmt.Println(green + `+------------------+              +------------------+`)
	fmt.Println(`|     pi-veth      |              |     pi-veth      |`)
	fmt.Println(`+------------------+              +------------------+`)
	fmt.Println(`          |                               |`)
	fmt.Println(green + `+------------------+              +------------------+`)
	fmt.Println(`|     br-int       |              |     br-int       |`)
	fmt.Println(`+------------------+              +------------------+`)
	fmt.Println(`          |                               |`)
	fmt.Println(green + `+------------------+              +------------------+`)
	fmt.Println(`| br-int_vxlan0    |              | br-int_vxlan0    |`)
	fmt.Println(`+------------------+              +------------------+`)
	fmt.Println(`          |                               |`)
	fmt.Println(green + `+------------------+              +------------------+`)
	fmt.Println(`| vxlan_sys_8472   |              | vxlan_sys_8472   |`)
	fmt.Println(`+------------------+              +------------------+`)
	fmt.Println(`          |                               |`)
	fmt.Println(green + `+------------------+              +------------------+`)
	fmt.Println(`| eth0.InfraVlan   |              | eth0.InfraVlan   |`)
	fmt.Println(`+------------------+              +------------------+`)
	fmt.Println(`          |                               |`)
	fmt.Println(green + `+------------------+              +------------------+`)
	fmt.Println(`|      node-1      |              |      node-2      |`)
	fmt.Println(`+------------------+              +------------------+`)
	fmt.Println(`          |                               |`)
	fmt.Println(`          |        +--------------+       |`)
	fmt.Println(`          ---------|  ACI-FABRIC  |--------`)
	fmt.Println(`                   +--------------+` + reset)
	fmt.Println()
	fmt.Println()
}

var PodtoPodtraceCmd = &cobra.Command{
	Use:     "trace_pod_to_pod [src_ns:src_pod] [dest_ns:dest_pod]",
	Short:   "Trace ip packet's flow in ovs for pod to pod communication",
	Example: `acikubectl trace_pod_to_pod src_ns:src_pod dest_ns:dest_pod --tcp --tcp_src <source_port> --tcp_dst <destination_port> --gbp --policy --endpoint --username <username> --apic <apic_ip>`,
	Args:    cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		pod_to_pod_tracepacket(args, tcpFlag, tcpSrc, tcpDst, verbose, gbp, policy, endpoint, username, apic)
	},
}

var PodtoSvctraceCmd = &cobra.Command{
	Use:     "trace_pod_to_svc [src_ns:src_pod] [dest_ns:dest_svc]",
	Short:   "Trace ip packet's flow in ovs from pod to service communication",
	Example: `acikubectl trace_pod_to_svc src_ns:src_pod dest_ns:dest_svc --tcp --tcp_src <source_port> --tcp_dst <destination_port>`,
	Args:    cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		pod_to_svc_tracepacket(args, tcpFlag, tcpSrc, tcpDst, verbose)
	},
}

var PodtoExttraceCmd = &cobra.Command{
	Use:     "trace_pod_to_ext [src_ns:src_pod] [dest_ip]",
	Short:   "Trace ip packet's flow in ovs from pod to outside cluster communication",
	Example: `acikubectl trace_pod_to_ext src_ns:src_pod dest_ip --tcp --tcp_src <source_port> --tcp_dst <destination_port>`,
	Args:    cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		pod_to_ext_tracepacket(args, tcpFlag, tcpSrc, tcpDst, verbose)
	},
}

func init() {
	nodeIdMaps = NewNodeIdMaps()
	RootCmd.AddCommand(PodtoPodtraceCmd)
	RootCmd.AddCommand(PodtoSvctraceCmd)
	RootCmd.AddCommand(PodtoExttraceCmd)
}

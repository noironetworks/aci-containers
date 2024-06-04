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
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"net/url"
	"os"
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
}

var nodeIdMaps *NodeIdMaps
var tcpFlag bool
var tcpSrc int
var tcpDst int
var verbose bool

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
	"NXM_NX_REG0":  "sEPG",
	"NXM_NX_REG2":  "dEPG",
	"NXM_NX_REG4":  "bdId",
	"NXM_NX_REG5":  "fgrpId",
	"NXM_NX_REG6":  "rdId",
	"NXM_NX_REG7":  "OutputPort",
	"NXM_NX_REG8":  "serviceAddr",
	"NXM_NX_REG9":  "ipv6ServiceAddr",
	"NXM_NX_REG10": "ipv6ServiceAddr",
	"NXM_NX_REG11": "ipv6ServiceAddr",
	"NXM_NX_REG12": "ctMark",
}

var BrAccessMetadataMap = map[string]string{
	"0x1":   "POP_VLAN",
	"0x2":   "PUSH_VLAN",
	"0x200": "EGRESS_DIR",
	"0x800": "DROP_LOG",
}

var BrIntMetadataMap = map[string]string{
	"0x100": "POLICY_APPLIED",
	"0x200": "FROM_SERVICE_INTERFACE",
	"0x400": "ROUTED",
	"0x800": "DROP_LOG",
	"0x1":   "RESUBMIT_DST",
	"0x2":   "NAT",
	"0x3":   "REV_NAT",
	"0x4":   "TUNNEL",
	"0x5":   "FLOOD",
	"0x7":   "REMOTE_TUNNEL",
	"0x8":   "HOST_ACCESS",
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
		fmt.Fprintf(&buffer, "%sTable %d:%s - %s\n", ColorYellow, table, ColorReset, tableDescriptions[table])
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
						fmt.Fprintf(&buffer, "  Loading register: %s(%s) -> %s %s(%s)%s\n", loadAction[0], pol_obj, register, ColorGreen, registerValue, ColorReset)
					} else {
						id_hex := strings.Split(loadAction[0], ":")[1]
						id_int, _ := strconv.ParseInt(id_hex, 0, 64)

						fmt.Fprintf(&buffer, "  Loading register: %s(%d) -> %s %s(%s)%s\n", loadAction[0], id_int, register, ColorGreen, registerValue, ColorReset)
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
						fmt.Fprintf(&buffer, "  Output to port: %s->%s\n", output, out_port_name)
						summary.OutPort = outPort
					}

				} else if strings.HasPrefix(action, "-> output") {
					outputParts := strings.Split(action, "->")

					if strings.Contains(outputParts[1], "to ") {
						outPort = strings.Split(outputParts[1], "to ")[1]
						//out_port_name := findPortName(outPort, bridgName, br.ovsPod)
						fmt.Fprintf(&buffer, " Out port:%s\n", outPort)
						summary.OutPort = outPort
					}
					if strings.Contains(outputParts[1], "is ") {
						outPort = strings.Split(outputParts[1], "is ")[1]
						out_port_name := findPortName(outPort, bridgName, br.ovsPod)
						fmt.Fprintf(&buffer, " Out port:%s->%s", outPort, out_port_name)
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
					fieldValue := strings.TrimSpace(strings.Split(setFieldAction[0], ":")[1])
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
					fmt.Fprintf(&buffer, "    Tunnel ID is now %s %s(decimal: %d)%s\n", tunnelID, ColorGreen, tunnelIDInt, ColorReset)
					summary.TunnelID = fmt.Sprintf("TunnelID:%s (decimal: %d)\n", tunnelID, tunnelIDInt)
				} else if strings.HasPrefix(action, "-> NXM_NX_TUN_IPV4_DST") {
					// Extract the value moved to the IPv4 destination address
					ipv4Dest := strings.Split(action, " is now ")[1]
					fmt.Fprintf(&buffer, "    IPv4 Destination is now %s\n", ipv4Dest)
				} else if strings.Contains(action, "Final flow") || strings.Contains(action, "Megaflow") {
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
		"--", "/bin/sh", "-c", fmt.Sprintf("ovs-ofctl show %s | grep -E ' %s\\([^)]+\\):'", bridgName, port)}

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
				port_name := strings.Split(ports, port)[1]
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
	PodtoSvctraceCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	PodtoSvctraceCmd.Flags().BoolVar(&tcpFlag, "tcp", false, "Specify if the protocol is TCP")
	PodtoSvctraceCmd.Flags().IntVar(&tcpSrc, "tcp_src", 0, "Specify the source TCP port")
	PodtoSvctraceCmd.Flags().IntVar(&tcpDst, "tcp_dst", 0, "Specify the destination TCP port")
}

func pod_to_pod_tracepacket(args []string, tcpFlag bool, tcpSrc int, tcpDst int, verbose bool) {
	if tcpFlag {
		if tcpSrc == 0 && tcpDst == 0 {
			fmt.Println("Error: If tcp is specified, either tcp_src or tcp_dst must be provided.")
			os.Exit(1)
		} else if tcpSrc == 0 {
			tcpSrc = 12345
		} else if tcpDst == 0 {
			tcpDst = 12345
		}
	}

	// Extract the arguments
	srcnspod := args[0]
	destnspod := args[1]

	// Split the arguments to separate namespace and pod
	srcns, srcpodname, err := splitNamespaceAndPod(srcnspod)
	if err != nil {
		fmt.Println(err)
		return
	}

	destns, destpodname, err := splitNamespaceAndPod(destnspod)
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
		fmt.Fprintf(os.Stderr, "Could not find %s namespace: %s\n", srcns)
		return
	}

	is_dest_ns_valid := validNamespace(kubeClient, destns)
	if !is_dest_ns_valid {
		fmt.Fprintf(os.Stderr, "Could not find %s namespace: %s\n", destns)
		return
	}

	srcPod, err := getPod(kubeClient, srcns, srcpodname)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not find source pod:", err)
	}

	destPod, err := getPod(kubeClient, destns, destpodname)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not find destination pod:", err)
	}

	srcOvsPodName, err := podForNode(kubeClient, "aci-containers-system",
		srcPod.Spec.NodeName, "name=aci-containers-openvswitch")

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	destOvsPodName := ""
	if destPod.Spec.NodeName != srcPod.Spec.NodeName {
		destOvsPodName, err = podForNode(kubeClient, "aci-containers-system",
			destPod.Spec.NodeName, "name=aci-containers-openvswitch")

		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	} else {
		destOvsPodName = srcOvsPodName
	}

	src_opflex_pod := ""
	dst_opflex_pod := ""

	src_ep, src_opflex_pod, err := findEp(kubeClient, srcPod)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)

	}

	dest_ep, dst_opflex_pod, err := findEp(kubeClient, destPod)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)

	}

	if _, ok := nodeIdMaps.nodeMaps[srcPod.Spec.NodeName]; !ok {
		err := buildIdMaps(srcPod.Spec.NodeName, src_opflex_pod)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)

		}
	}

	//Source Calculation
	src_buffer := new(bytes.Buffer)

	cmd_args := []string{}
	if !tcpFlag {
		cmd_args = []string{"exec", "-n", "aci-containers-system", srcOvsPodName,
			"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-access 'in_port=%s, ip, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s'", src_ep.Attributes.InterfaceName,
				srcPod.Status.PodIP, destPod.Status.PodIP, src_ep.Mac, dest_ep.Mac)}
	} else {
		cmd_args = []string{"exec", "-n", "aci-containers-system", srcOvsPodName,
			"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-access 'in_port=%s, tcp, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s,tcp_src=%d,tcp_dst=%d'", src_ep.Attributes.InterfaceName,
				srcPod.Status.PodIP, destPod.Status.PodIP, src_ep.Mac, dest_ep.Mac, tcpSrc, tcpDst)}
	}

	err = execKubectl(cmd_args, src_buffer)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)

	}

	// Split the buffer into sections
	sections := strings.Split(src_buffer.String(), "bridge")

	out_bridgeflows := []Bridge{}

	for idx, section := range sections {
		if strings.Contains(section, "br-access") {
			out_bridgeflows = append(out_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" + section, nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
		} else if idx > 0 && strings.Contains(sections[idx-1], "br-access") && strings.Contains(sections[idx-1], "resume conntrack") {
			//out_bridgeflows[len(out_bridgeflows)-1].brFlows += "\n" + section
			out_bridgeflows = append(out_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" + section, nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
		} else if strings.Contains(section, "br-int") {
			out_bridgeflows = append(out_bridgeflows, Bridge{br_type: "br-int", brFlows: "bridge" + section, nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
		}
	}

	for idx, _ := range out_bridgeflows {
		out_bridgeflows[idx].brFlowEntries = out_bridgeflows[idx].parseFlowEntries()
		out_bridgeflows[idx].out_br_buff = out_bridgeflows[idx].buildPacketTrace()
	}

	var packetDropped bool
	fmt.Printf("\n\n%s%s%s", ColorGreen, "\nSummary\n", ColorReset)

	for _, br := range out_bridgeflows {
		if br.summary != nil && br.summary.PacketDropped {
			if br.br_type == "br-access" {
				fmt.Printf("%sPacket dropped on bridge: %s and in table%d: %s on node: %s%s\n", ColorRed, "br-access", br.summary.previousTable, brAccessTableDescriptions[br.summary.previousTable], srcPod.Spec.NodeName, ColorReset)
				packetDropped = true
			} else {
				fmt.Printf("%sPacket dropped on bridge: %s and in table%d: %s on node: %s%s\n", ColorRed, "br-int", br.summary.previousTable, brIntTableDescriptions[br.summary.previousTable], srcPod.Spec.NodeName, ColorReset)
				packetDropped = true
			}
		}
	}

	//Find gbpObjects
	gbpObjects, err := findGbpPolicy(kubeClient, destPod)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	//Destination Calculation
	tun_id, err := findTunnelId(gbpObjects, dest_ep)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	tun_id_int, _ := strconv.ParseInt("0x"+tun_id, 0, 64)

	if !packetDropped {
		if srcPod.Spec.NodeName != destPod.Spec.NodeName {
			fmt.Printf("%sPacket sent out from node:%s with source_epg %s(%s) to destination_epg with TunnelID:0x%s(decimal:%d)(%s) %s\n",
				ColorGreen, srcPod.Spec.NodeName, out_bridgeflows[len(out_bridgeflows)-1].summary.TunnelID, src_ep.EndpointGroupName, tun_id, tun_id_int, dest_ep.EndpointGroupName, ColorReset)
		} else {
			fmt.Printf("%sPacket sent out and recieved on same node: %s%s\n", ColorGreen, srcPod.Spec.NodeName, ColorReset)
		}
	}

	in_bridgeflows := []Bridge{}

	if !packetDropped && srcPod.Spec.NodeName != destPod.Spec.NodeName {

		if _, ok := nodeIdMaps.nodeMaps[destPod.Spec.NodeName]; !ok {
			err := buildIdMaps(destPod.Spec.NodeName, dst_opflex_pod)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)

			}
		}

		dest_buffer := new(bytes.Buffer)
		if !tcpFlag {
			cmd_args = []string{"exec", "-n", "aci-containers-system", destOvsPodName,
				"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-int 'in_port=vxlan0,tun_id=0x%s, ip, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s'",
					tun_id, srcPod.Status.PodIP, destPod.Status.PodIP, src_ep.Mac, dest_ep.Mac)}
		} else {
			cmd_args = []string{"exec", "-n", "aci-containers-system", destOvsPodName,
				"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-int 'in_port=vxlan0,tun_id=0x%s, tcp, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s,tcp_src=%d,tcp_dst=%d'",
					tun_id, srcPod.Status.PodIP, destPod.Status.PodIP, src_ep.Mac, dest_ep.Mac, tcpSrc, tcpDst)}
		}

		err = execKubectl(cmd_args, dest_buffer)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)

		}

		sections = strings.Split(dest_buffer.String(), "bridge")

		for idx, section := range sections {
			if strings.Contains(section, "br-access") {
				//brAccessFlows = "bridge" + section
				in_bridgeflows = append(in_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" + section, nodename: destPod.Spec.NodeName, ovsPod: destOvsPodName, opflexPod: dst_opflex_pod})
			} else if idx > 0 && strings.Contains(sections[idx-1], "br-access") && strings.Contains(sections[idx-1], "resume conntrack") {
				//brAccessFlows += "\n" + section
				in_bridgeflows = append(in_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" + section, nodename: destPod.Spec.NodeName, ovsPod: destOvsPodName, opflexPod: dst_opflex_pod})
				//in_bridgeflows[len(in_bridgeflows)-1].brFlows += "\n" + section
			} else if strings.Contains(section, "br-int") {
				//brIntFlows = "bridge" + section
				in_bridgeflows = append(in_bridgeflows, Bridge{br_type: "br-int", brFlows: "bridge" + section, nodename: destPod.Spec.NodeName, ovsPod: destOvsPodName, opflexPod: dst_opflex_pod})
			}
		}

		for idx, _ := range in_bridgeflows {
			in_bridgeflows[idx].brFlowEntries = in_bridgeflows[idx].parseFlowEntries()
			in_bridgeflows[idx].out_br_buff = in_bridgeflows[idx].buildPacketTrace()
		}

		for _, br := range in_bridgeflows {
			if br.summary != nil && br.summary.PacketDropped {
				if br.br_type == "br-int" {
					fmt.Printf("%sPacket dropped on bridge: %s and in table%d: %s on node: %s%s\n", ColorRed, "br-int", br.summary.previousTable, brIntTableDescriptions[br.summary.previousTable], destPod.Spec.NodeName, ColorReset)

				} else {
					fmt.Printf("%sPacket dropped on bridge: %s and in table%d: %s on node: %s%s\n", ColorRed, "br-access", br.summary.previousTable, brAccessTableDescriptions[br.summary.previousTable], destPod.Spec.NodeName, ColorReset)
				}
			}
		}

		//else {
		//	if srcPod.Spec.NodeName != destPod.Spec.NodeName {
		//		fmt.Printf("%sPacket recieved from node:%s with TunID: %s%s\n", ColorGreen, destPod.Spec.NodeName, summaryBrInt.TunnelID, ColorReset)
		//	} else {
		//		fmt.Printf("%sPacket sent out and recieved on same node: %s%s\n", ColorGreen, destPod.Spec.NodeName, ColorReset)
		//	}
		//
		//}
		//

	}

	if verbose {
		fmt.Printf("\n\n%s%s%s", ColorGreen, "Detailed Explanation", ColorReset)
		fmt.Printf("\n\n%s%s%s", ColorRed, "Outgoing Packet", ColorReset)
		for _, br := range out_bridgeflows {
			if br.br_type == "br-access" {
				fmt.Printf("\n%s%s%s\n", ColorBlue, "br-access:", ColorReset)
				fmt.Println(br.out_br_buff)
			} else {
				fmt.Printf("\n%s%s%s\n", ColorBlue, "br-int:", ColorReset)
				fmt.Println(br.out_br_buff)
			}

		}

		if !packetDropped && srcPod.Spec.NodeName != destPod.Spec.NodeName {
			fmt.Printf("\n\n%s%s%s", ColorRed, "Incoming Packet", ColorReset)
			for _, br := range in_bridgeflows {
				if br.br_type == "br-access" {
					fmt.Printf("\n%s%s%s\n", ColorBlue, "br-access:", ColorReset)
					fmt.Println(br.out_br_buff)
				} else {
					fmt.Printf("\n%s%s%s\n", ColorBlue, "br-int:", ColorReset)
					fmt.Println(br.out_br_buff)
				}

			}
		}
	}

}

func pod_to_svc_tracepacket(args []string, tcpFlag bool, tcpSrc int, tcpDst int, verbose bool) {
	if tcpFlag {
		if tcpSrc == 0 && tcpDst == 0 {
			fmt.Println("Error: If tcp is specified, either tcp_src or tcp_dst must be provided.")
			os.Exit(1)
		} else if tcpSrc == 0 {
			tcpSrc = 12345
		}
	} else {
		fmt.Println("Error: tcp protocol must be provided.")
		os.Exit(1)
	}

	// Extract the arguments
	srcnspod := args[0]
	destnssvc := args[1]

	// Split the arguments to separate namespace and pod
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
		fmt.Fprintf(os.Stderr, "Could not find %s namespace: %s\n", srcns)
		return
	}

	is_dest_ns_valid := validNamespace(kubeClient, destns)
	if !is_dest_ns_valid {
		fmt.Fprintf(os.Stderr, "Could not find %s namespace: %s\n", destns)
		return
	}

	srcPod, err := getPod(kubeClient, srcns, srcpodname)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not find source pod:", err)
	}

	svc, err := getSvc(kubeClient, destns, destsvcname)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not find destination svc:", err)
	}

	srcOvsPodName, err := podForNode(kubeClient, "aci-containers-system",
		srcPod.Spec.NodeName, "name=aci-containers-openvswitch")

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	//destOvsPodName := ""
	//if destPod.Spec.NodeName != srcPod.Spec.NodeName {
	//	destOvsPodName, err = podForNode(kubeClient, "aci-containers-system",
	//		destPod.Spec.NodeName, "name=aci-containers-openvswitch")
	//
	//	if err != nil {
	//		fmt.Fprintln(os.Stderr, err)
	//	}
	//} else {
	//	destOvsPodName = srcOvsPodName
	//}

	src_opflex_pod := ""

	src_ep, src_opflex_pod, err := findEp(kubeClient, srcPod)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)

	}

	dest_svc, err := findService(kubeClient, srcPod, destsvcname)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)

	}

	if _, ok := nodeIdMaps.nodeMaps[srcPod.Spec.NodeName]; !ok {
		err := buildIdMaps(srcPod.Spec.NodeName, src_opflex_pod)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)

		}
	}

	//Source Calculation
	src_buffer := new(bytes.Buffer)

	cmd_args := []string{}

	cmd_args = []string{"exec", "-n", "aci-containers-system", srcOvsPodName,
		"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-access 'in_port=%s, tcp, nw_ttl=10, nw_src=%s, nw_dst=%s, dl_src=%s, tcp_src=%d,tcp_dst=%d'", src_ep.Attributes.InterfaceName,
			srcPod.Status.PodIP, dest_svc.ServiceMapping[0].ServiceIp, src_ep.Mac, tcpSrc, tcpDst)}

	err = execKubectl(cmd_args, src_buffer)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)

	}

	// Split the buffer into sections
	sections := strings.Split(src_buffer.String(), "bridge")

	out_bridgeflows := []Bridge{}

	for idx, section := range sections {
		if strings.Contains(section, "br-access") {
			out_bridgeflows = append(out_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" + section, nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
		} else if idx > 0 && strings.Contains(sections[idx-1], "br-access") && strings.Contains(sections[idx-1], "resume conntrack") {
			//out_bridgeflows[len(out_bridgeflows)-1].brFlows += "\n" + section
			out_bridgeflows = append(out_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" + section, nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
		} else if strings.Contains(section, "br-int") {
			out_bridgeflows = append(out_bridgeflows, Bridge{br_type: "br-int", brFlows: "bridge" + section, nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
		}
	}

	for idx, _ := range out_bridgeflows {
		out_bridgeflows[idx].brFlowEntries = out_bridgeflows[idx].parseFlowEntries()
		out_bridgeflows[idx].out_br_buff = out_bridgeflows[idx].buildPacketTrace()
	}

	var packetDropped bool
	var destPodIp string
	var destPod *v1.Pod
	//var dst_opflex_pod string

	for _, br := range out_bridgeflows {
		if br.summary != nil && br.summary.PacketDropped {
			if br.br_type == "br-access" {
				fmt.Printf("\n\n%s%s%s", ColorGreen, "\nSummary\n", ColorReset)
				fmt.Printf("%sPacket dropped on bridge: %s and in table%d: %s on node: %s%s\n", ColorRed, "br-access", br.summary.previousTable, brAccessTableDescriptions[br.summary.previousTable], srcPod.Spec.NodeName, ColorReset)
				packetDropped = true
			} else {
				fmt.Printf("\n\n%s%s%s", ColorGreen, "\nSummary\n", ColorReset)
				fmt.Printf("%sPacket dropped on bridge: %s and in table%d: %s on node: %s%s\n", ColorRed, "br-int", br.summary.previousTable, brIntTableDescriptions[br.summary.previousTable], srcPod.Spec.NodeName, ColorReset)
				packetDropped = true
			}
		}

		if br.summary != nil && br.br_type == "br-int" && br.summary.ip_dst != "" {
			destPodIp = br.summary.ip_dst
		}
	}

	if !packetDropped {

		if destPodIp != "" {
			destPod, err = findPodByIP(kubeClient, destns, destPodIp)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Could not find destination pod:", err)

			}
		}

		if destPod != nil {
			//dest_ep, dst_opflex_pod, err := findEp(kubeClient, destPod)
			dest_ep, _, err := findEp(kubeClient, destPod)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)

			}

			//Find gbpObjects
			gbpObjects, err := findGbpPolicy(kubeClient, destPod)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
			}

			//Destination Calculation
			tun_id, err := findTunnelId(gbpObjects, dest_ep)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
			}

			tun_id_int, _ := strconv.ParseInt("0x"+tun_id, 0, 64)

			if srcPod.Spec.NodeName != destPod.Spec.NodeName {
				fmt.Printf("\n\n%s%s%s", ColorGreen, "\nSummary\n", ColorReset)
				fmt.Printf("%sPacket sent out from node:%s with source_epg %s(%s) to destination svc ip %s which translates to endpoint %s(IP->%s) with destination_epg/TunnelID:0x%s(decimal:%d)(%s) %s\n",
					ColorGreen, srcPod.Spec.NodeName, out_bridgeflows[len(out_bridgeflows)-1].summary.TunnelID, src_ep.EndpointGroupName, svc.Spec.ClusterIP, destPod.Name, destPod.Status.PodIP, tun_id, tun_id_int, dest_ep.EndpointGroupName, ColorReset)
			} else {
				fmt.Printf("\n\n%s%s%s", ColorGreen, "\nSummary\n", ColorReset)
				fmt.Printf("%sPacket sent out to destination svc ip %s which translates to endpoint %s(IP->%s) and recieved on same node: %s %s\n", ColorGreen, svc.Spec.ClusterIP, destPod.Name, destPod.Status.PodIP, srcPod.Spec.NodeName, ColorReset)
			}
		}

	}

	//
	//in_bridgeflows := []Bridge{}

	//if !packetDropped && srcPod.Spec.NodeName != destPod.Spec.NodeName {
	//
	//	if _, ok := nodeIdMaps.nodeMaps[destPod.Spec.NodeName]; !ok {
	//		err := buildIdMaps(destPod.Spec.NodeName, dst_opflex_pod)
	//		if err != nil {
	//			fmt.Fprintln(os.Stderr, err)
	//
	//		}
	//	}

	//dest_buffer := new(bytes.Buffer)
	//if !tcpFlag {
	//	cmd_args = []string{"exec", "-n", "aci-containers-system", destOvsPodName,
	//		"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-int 'in_port=vxlan0,tun_id=0x%s, ip, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s'",
	//			tun_id, srcPod.Status.PodIP, destPod.Status.PodIP, src_ep.Mac, dest_ep.Mac)}
	//} else {
	//	cmd_args = []string{"exec", "-n", "aci-containers-system", destOvsPodName,
	//		"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-int 'in_port=vxlan0,tun_id=0x%s, tcp, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s,tcp_src=%d,tcp_dst=%d'",
	//			tun_id, srcPod.Status.PodIP, destPod.Status.PodIP, src_ep.Mac, dest_ep.Mac, tcpSrc, tcpDst)}
	//}
	//
	//err = execKubectl(cmd_args, dest_buffer)
	//if err != nil {
	//	fmt.Fprintln(os.Stderr, err)
	//
	//}
	//
	//sections = strings.Split(dest_buffer.String(), "bridge")
	//
	//for idx, section := range sections {
	//	if strings.Contains(section, "br-access") {
	//		//brAccessFlows = "bridge" + section
	//		in_bridgeflows = append(in_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" + section, nodename: destPod.Spec.NodeName, ovsPod: destOvsPodName, opflexPod: dst_opflex_pod})
	//	} else if idx > 0 && strings.Contains(sections[idx-1], "br-access") && strings.Contains(sections[idx-1], "resume conntrack") {
	//		//brAccessFlows += "\n" + section
	//		in_bridgeflows = append(in_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" + section, nodename: destPod.Spec.NodeName, ovsPod: destOvsPodName, opflexPod: dst_opflex_pod})
	//		//in_bridgeflows[len(in_bridgeflows)-1].brFlows += "\n" + section
	//	} else if strings.Contains(section, "br-int") {
	//		//brIntFlows = "bridge" + section
	//		in_bridgeflows = append(in_bridgeflows, Bridge{br_type: "br-int", brFlows: "bridge" + section, nodename: destPod.Spec.NodeName, ovsPod: destOvsPodName, opflexPod: dst_opflex_pod})
	//	}
	//}
	//
	//for idx, _ := range in_bridgeflows {
	//	in_bridgeflows[idx].brFlowEntries = in_bridgeflows[idx].parseFlowEntries()
	//	in_bridgeflows[idx].out_br_buff = in_bridgeflows[idx].buildPacketTrace()
	//}
	//
	//for _, br := range in_bridgeflows {
	//	if br.summary != nil && br.summary.PacketDropped {
	//		if br.br_type == "br-int" {
	//			fmt.Printf("%sPacket dropped on bridge: %s and in table%d: %s on node: %s%s\n", ColorRed, "br-int", br.summary.previousTable, brIntTableDescriptions[br.summary.previousTable], destPod.Spec.NodeName, ColorReset)
	//
	//		} else {
	//			fmt.Printf("%sPacket dropped on bridge: %s and in table%d: %s on node: %s%s\n", ColorRed, "br-access", br.summary.previousTable, brAccessTableDescriptions[br.summary.previousTable], destPod.Spec.NodeName, ColorReset)
	//		}
	//	}
	//}

	//else {
	//	if srcPod.Spec.NodeName != destPod.Spec.NodeName {
	//		fmt.Printf("%sPacket recieved from node:%s with TunID: %s%s\n", ColorGreen, destPod.Spec.NodeName, summaryBrInt.TunnelID, ColorReset)
	//	} else {
	//		fmt.Printf("%sPacket sent out and recieved on same node: %s%s\n", ColorGreen, destPod.Spec.NodeName, ColorReset)
	//	}
	//
	//}
	//

	//}

	if verbose {
		fmt.Printf("\n\n%s%s%s", ColorGreen, "Detailed Explanation", ColorReset)
		fmt.Printf("\n\n%s%s%s", ColorRed, "Outgoing Packet", ColorReset)
		for _, br := range out_bridgeflows {
			if br.br_type == "br-access" {
				fmt.Printf("\n%s%s%s\n", ColorBlue, "br-access:", ColorReset)
				fmt.Println(br.out_br_buff)
			} else {
				fmt.Printf("\n%s%s%s\n", ColorBlue, "br-int:", ColorReset)
				fmt.Println(br.out_br_buff)
			}

		}

		//if !packetDropped && srcPod.Spec.NodeName != destPod.Spec.NodeName {
		//	fmt.Printf("\n\n%s%s%s", ColorRed, "Incoming Packet", ColorReset)
		//	for _, br := range in_bridgeflows {
		//		if br.br_type == "br-access" {
		//			fmt.Printf("\n%s%s%s\n", ColorBlue, "br-access:", ColorReset)
		//			fmt.Println(br.out_br_buff)
		//		} else {
		//			fmt.Printf("\n%s%s%s\n", ColorBlue, "br-int:", ColorReset)
		//			fmt.Println(br.out_br_buff)
		//		}
		//
		//	}
		//}
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

func findEp(kubeClient kubernetes.Interface, pod *v1.Pod) (EndPoints, string, error) {
	hostPodName, err := podForNode(kubeClient, "aci-containers-system",
		pod.Spec.NodeName, "name=aci-containers-host")

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return EndPoints{}, "", err
	}

	ep_buffer := new(bytes.Buffer)
	cmd_args := []string{"exec", "-n", "aci-containers-system", hostPodName, "-c", "opflex-agent",
		"--", "/bin/sh", "-c", fmt.Sprintf("for file in $(grep -l %s /usr/local/var/lib/opflex-agent-ovs/endpoints/*); do cat $file; done", pod.Status.PodIP)}

	err = execKubectl(cmd_args, ep_buffer)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return EndPoints{}, "", err
	}

	if ep_buffer.Len() == 0 {
		return EndPoints{}, "", errors.New("no endpoints found")
	}

	//Convert ep_buffer to Endpoint
	var ep EndPoints

	// Unmarshal the JSON data from ep_buffer into the EndPoints struct
	err = json.Unmarshal(ep_buffer.Bytes(), &ep)
	if err != nil {
		fmt.Println("Error:", err)
		return EndPoints{}, "", err
	}

	// Print the EP details
	printEndpointDetails(ep, pod, hostPodName)
	return ep, hostPodName, nil
}

func findService(kubeClient kubernetes.Interface, pod *v1.Pod, svcname string) (Service, error) {
	hostPodName, err := podForNode(kubeClient, "aci-containers-system",
		pod.Spec.NodeName, "name=aci-containers-host")

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return Service{}, err
	}

	svc_buffer := new(bytes.Buffer)
	cmd_args := []string{"exec", "-n", "aci-containers-system", hostPodName, "-c", "opflex-agent",
		"--", "/bin/sh", "-c", fmt.Sprintf("for file in $(grep -l %s /usr/local/var/lib/opflex-agent-ovs/services/*); do cat $file; done", svcname)}

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

	// Print the EP details
	printServiceDetails(svc)
	return svc, nil
}

func printEndpointDetails(ep EndPoints, pod *v1.Pod, hostPodName string) {
	fmt.Printf("\n%s EP Details:", pod.Name)
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "UUID:\t%s\n", ep.Uuid)
	fmt.Fprintf(w, "EgPolicySpace:\t%s\n", ep.EgPolicySpace)
	fmt.Fprintf(w, "EndpointGroupName:\t%s\n", ep.EndpointGroupName)
	fmt.Fprintf(w, "QoS Policy:\t%v\n", ep.QosPolicy)
	fmt.Fprintf(w, "IP:\t%v\n", ep.Ip)
	fmt.Fprintf(w, "MAC Address:\t%s\n", ep.Mac)
	fmt.Fprintf(w, "Access Interface:\t%s\n", ep.AccessInterface)
	fmt.Fprintf(w, "Access Uplink Interface:\t%s\n", ep.AccessUplinkInterface)
	fmt.Fprintf(w, "Interface Name:\t%s\n", ep.InterfaceName)
	fmt.Fprintf(w, "Namespace:\t%s\n", ep.Attributes.Namespace)
	fmt.Fprintf(w, "VM Name:\t%s\n", ep.Attributes.VmName)
	fmt.Fprintf(w, "Pod Name:\t%s\n", pod.Name)
	fmt.Fprintf(w, "Node Name:\t%s\n", pod.Spec.NodeName)
	w.Flush()

	fmt.Println()
}

func printServiceDetails(svc Service) {
	fmt.Printf("\nService Details:")
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "UUID:\t%s\n", svc.Uuid)
	fmt.Fprintf(w, "Domain Policy Space:\t%s\n", svc.DomainPolicySpace)
	fmt.Fprintf(w, "Domain Name:\t%s\n", svc.DomainName)
	fmt.Fprintf(w, "Service Mode:\t%s\n", svc.ServiceMode)
	fmt.Fprintf(w, "Service Type:\t%s\n", svc.ServiceType)
	fmt.Fprintf(w, "Attributes Name:\t%s\n", svc.Attributes.Name)
	fmt.Fprintf(w, "Namespace:\t%s\n", svc.Attributes.Namespace)
	fmt.Fprintf(w, "Service Name:\t%s\n", svc.Attributes.ServiceName)

	for _, mapping := range svc.ServiceMapping {
		fmt.Fprintf(w, "Service IP:\t%s\n", mapping.ServiceIp)
		fmt.Fprintf(w, "Service Protocol:\t%s\n", mapping.ServiceProto)
		fmt.Fprintf(w, "Service Port:\t%d\n", mapping.ServicePort)
		fmt.Fprintf(w, "Next Hop IPs:\t%v\n", mapping.NextHopIps)
		fmt.Fprintf(w, "Next Hop Port:\t%d\n", mapping.NextHopPort)
		fmt.Fprintf(w, "Conntrack Enabled:\t%v\n", mapping.ConntrackEnabled)
		fmt.Fprintf(w, "Node Port:\t%d\n", mapping.NodePort)
		fmt.Fprintf(w, "Session Affinity Timeout Seconds:\t%d\n", mapping.SessionAffinity.ClientIp.TimeoutSeconds)
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

var PodtoPodtraceCmd = &cobra.Command{
	Use:     "traceptp [src_ns:src_pod] [dest_ns:dest_pod]",
	Short:   "Trace ip packet's flow in ovs for pod to pod communication",
	Example: `acikubectl trace src_ns:src_pod dest_ns:dest_pod --tcp --tcp_src <source_port> --tcp_dst <destination_port>`,
	Args:    cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		pod_to_pod_tracepacket(args, tcpFlag, tcpSrc, tcpDst, verbose)
	},
}

var PodtoSvctraceCmd = &cobra.Command{
	Use:     "traceptsvc [src_ns:src_pod] [dest_ns:dest_svc]",
	Short:   "Trace ip packet's flow in ovs from pod to service communication",
	Example: `acikubectl trace src_ns:src_pod dest_ns:dest_svc --tcp --tcp_src <source_port> --tcp_dst <destination_port>`,
	Args:    cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		pod_to_svc_tracepacket(args, tcpFlag, tcpSrc, tcpDst, verbose)
	},
}

func init() {
	nodeIdMaps = NewNodeIdMaps()
	RootCmd.AddCommand(PodtoPodtraceCmd)
	RootCmd.AddCommand(PodtoSvctraceCmd)
}

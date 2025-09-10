// Copyright  2024 Cisco Systems, Inc.
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
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

const (
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorRed    = "\033[31m"
	ColorPurple = "\033[35m"
	ColorReset  = "\033[0m"
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
	udp_dst       string
	ip_dst        string
	snat_ip       string
	ct_mark       string
}

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

type TpProto struct {
	Enabled    bool
	Protocol   string
	SrcPort    string
	SrcPortVal int
	DstPort    string
	DstPortVal int
}

var BrAccessRegisterMap = map[string]string{
	"NXM_NX_REG0": "SecGrpId",
	"NXM_NX_REG5": "VlanId",
	"NXM_NX_REG6": "ConnTrackZoneId",
	"NXM_NX_REG7": "OutputPort",
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

var BrAccessFileRegisterMap = map[string]string{
	"NXM_NX_REG0": "secGroupSet",
	"NXM_NX_REG6": "conntrack",
}
var BrIntFilesRegisterMap = map[string]string{
	"NXM_NX_REG4": "bridgeDomain",
	"NXM_NX_REG5": "floodDomain",
	"NXM_NX_REG6": "routingDomain",
	"NXM_NX_REG8": "service",
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
	"0x1": "RESUBMIT_DST: Indicates resubmit to the first dest table with the source registers set to " +
		"the corresponding values for the EPG in REG7",
	"0x2": "NAT: Indicates perform outbound NAT action and then resubmit with the source EPG set to the mapped NAT EPG",
	"0x3": "REV_NAT: Indicates Output to the interface in REG7, but intercept ICMP error replies and overwrite " +
		"the encapsulated error packet's source address with the (rewritten) destination address of the outer packet",
	"0x4": "TUNNEL: Indicates output to the tunnel destination appropriate for the EPG",
	"0x5": "FLOOD: Indicates output to the flood group appropriate for the EPG",
	"0x7": "REMOTE_TUNNEL: Indicates output to the tunnel destination specified in the output register",
	"0x8": "HOST_ACCESS: Indicates output to the veth_host_ac destination specified in output register",
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
	0: "DROP_LOGS (Handles drop log policy)",
	1: "SEC_TABLE (Handles port security/ingress policy)",
	2: "SRC_TABLE (Maps source addresses to endpoint groups and sets this mapping into registers for use by later " +
		"tables)",
	3: "SNAT_REV_TABLE (External World to SNAT IP: UN-SNAT traffic using connection tracking. Changes network " +
		"destination using state in connection tracker and forwards traffic to the endpoint.)",
	4: "SERVICE_REV_TABLE (For traffic returning from load-balanced service IP addresses, restore the source address to" +
		" the service address)",
	5: "BRIDGE_TABLE (\nFor flows that can be forwarded through bridging, it maps the destination L2 address to an " +
		"endpoint group and the next hop interface, then stores this mapping in registers for use by subsequent tables. " +
		"It also manages replies for protocols handled by the agent or switch, such as ARP and NDP)",
	6: "SERVICE_NEXTHOP_TABLE (For load-balanced service IPs, map from a bucket ID to the appropriate destination IP " +
		"address.)",
	7: "ROUTE_TABLE (For flows that require routing, maps the destination L3 address to an endpoint group or external " +
		"network and next hop action and sets this information into registers for use by later tables.)",
	8: "SNAT_TABLE (Endpoint -> External World: Traffic that needs SNAT is determined after routing local traffic. " +
		"SNAT changes the source IP address and source port based on configuration in the endpoint file.)",
	9: "NAT_IN_TABLE (For flows destined for a NAT IP address, determine the source external network for the mapped " +
		"IP address and set this in the source registers to allow applying policy to NATed flows.)",
	10: "LEARN_TABLE (Source for flows installed by OVS learn action)",
	11: "SERVICE_DST_TABLE (Map traffic returning from a service interface to the appropriate endpoint interface.)",
	12: "POL_TABLE (Allow policy for the flow based on the source and destination groups and the contracts that are " +
		"configured.)",
	13: "STATS_TABLE (Flow stats computation)",
	14: "OUT_TABLE (Apply a destination action based on the action set in the metadata field.)",
	15: "EXP_DROP_TABLE (Handle explicitly dropped packets here based on the drop-log config)",
	16: "NUM_FLOW_TABLES (The total number of flow tables)",
}

func initLogger() {
	logLevel := os.Getenv("LOG_LEVEL")
	switch strings.ToLower(logLevel) {
	case "debug":
		log.SetLevel(log.DebugLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
}

func wrapText(text string, width int) string {
	var wrappedText strings.Builder
	words := strings.Fields(text)
	line := ""
	for _, word := range words {
		// Check if adding the next word exceeds the width
		if len(line)+len(word)+1 > width {
			if line != "" {
				wrappedText.WriteString(line + "\n")
				line = ""
			}
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" {
		wrappedText.WriteString(line + "\n")
	}
	return wrappedText.String()
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
	// Iterate through the tables sequentially
	for _, table := range tableNumbers {
		fmt.Fprintf(&buffer, "%sTable %d: - %s%s\n", ColorYellow, table, wrapText(tableDescriptions[table],
			60), ColorReset)
		for _, flowentry := range flowEntries[table] {
			// Split the entry into actions
			criterias := strings.Split(flowentry, ", ")
			for _, criteria := range criterias {
				criteria = strings.TrimSpace(criteria)

				// Check for metadata and register loading
				if strings.HasPrefix(criteria, "write_metadata:") {
					metadata := strings.Split(criteria, ":")[1]
					metadataValue := mapMetadata(metadata, bridgName)
					fmt.Fprintf(&buffer, "  Writing metadata:\n  %s %s(%s)%s\n", metadata, ColorGreen,
						metadataValue, ColorReset)
				} else if strings.HasPrefix(criteria, "load:") {
					loadAction := strings.Split(criteria, "->")
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
						fmt.Fprintf(&buffer, "  Loading register:\n  %s%s(%s)%s -> %s %s(%s)%s\n", loadAction[0],
							ColorPurple, pol_obj, ColorReset, register, ColorGreen, registerValue,
							ColorReset)
					} else {
						id_hex := strings.Split(loadAction[0], ":")[1]
						id_int, _ := strconv.ParseInt(id_hex, 0, 64)

						fmt.Fprintf(&buffer, "  Loading register: %s%s(%d)%s -> %s %s(%s)%s\n", loadAction[0],
							ColorPurple, id_int, ColorReset, register, ColorGreen, registerValue, ColorReset)
					}

					if bridgName == "br-int" && register == "NXM_NX_REG12" {
						ct_mark = strings.Split(loadAction[0], ":")[1]
					}

				} else if strings.HasPrefix(criteria, "goto_table:") {
					next_table := strings.Split(criteria, ":")[1]
					fmt.Fprintf(&buffer, "  Going to table: %s\n", next_table)
					previousTable = table
				} else if strings.HasPrefix(criteria, "output:") {
					output := strings.Split(criteria, ":")[1]
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

				} else if strings.HasPrefix(criteria, "-> output") {
					outputParts := strings.Split(criteria, "->")

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

				} else if strings.HasPrefix(criteria, "in_port=") {
					inPort = strings.Split(criteria, "=")[1]
					inPort = strings.Split(inPort, ",")[0]
					in_port_name := findPortName(inPort, bridgName, br.ovsPod)
					fmt.Fprintf(&buffer, "  In port: %s->%s\n", inPort, in_port_name)
					summary.InPort = inPort
				} else if strings.HasPrefix(criteria, "move:") {
					moveAction := strings.Split(criteria, "->")
					moveSource := strings.Split(moveAction[0], ":")[1]
					moveTarget := strings.TrimSpace(moveAction[1])
					fmt.Fprintf(&buffer, "  Moving value from: %s to %s\n", moveSource, moveTarget)
				} else if strings.HasPrefix(criteria, "set_field:") {
					setFieldAction := strings.Split(criteria, "->")
					fieldName := strings.TrimSpace(setFieldAction[1])
					fieldValue := strings.TrimSpace(strings.Split(setFieldAction[0], "set_field:")[1])
					if fieldName == "tcp_dst" {
						summary.tcp_dst = fieldValue
					} else if fieldName == "udp_dst" {
						summary.udp_dst = fieldValue
					} else if fieldName == "ip_dst" {
						summary.ip_dst = fieldValue
					}
					fmt.Fprintf(&buffer, "  Setting field: %s to %s\n", fieldName, fieldValue)
				} else if strings.HasPrefix(criteria, "dec_ttl") {
					fmt.Fprintf(&buffer, "  Decrementing TTL\n")
				} else if strings.Contains(criteria, "-> NXM_NX_TUN_ID") {
					// Extract the value moved to the tunnel ID
					tunnelID = strings.Split(criteria, " is now ")[1]
					tunnelIDInt, _ := strconv.ParseInt(tunnelID, 0, 64)
					// Print the tunnel ID in both hexadecimal and decimal formats
					fmt.Fprintf(&buffer, "    VXLAN_Tunnel_ID is now %s %s(decimal: %d)%s\n", tunnelID, ColorGreen, tunnelIDInt, ColorReset)
					summary.TunnelID = fmt.Sprintf("VXLAN_Tunnel_ID:%s (decimal: %d)\n", tunnelID, tunnelIDInt)
				} else if strings.HasPrefix(criteria, "-> NXM_NX_TUN_IPV4_DST") {
					// Extract the value moved to the IPv4 destination address
					ipv4Dest := strings.Split(criteria, " is now ")[1]
					fmt.Fprintf(&buffer, "    IPv4 Destination is now %s\n", ipv4Dest)
				} else if strings.Contains(criteria, "nat(src=") && summary.snat_ip == "" {

					re := regexp.MustCompile(`nat\(src=(\d+\.\d+\.\d+\.\d+)`)

					match := re.FindStringSubmatch(criteria)
					if len(match) > 1 {
						ipAddress := match[1]
						fmt.Fprintf(&buffer, "%sSNAT IP is %s%s\n", ColorPurple, ipAddress, ColorReset)
						summary.snat_ip = ipAddress
					}
				} else if strings.Contains(criteria, "Final flow") ||
					strings.Contains(criteria, "Megaflow") || strings.Contains(criteria, "Datapath actions") {
					continue
				} else {
					re := regexp.MustCompile(`reg(\d+)=0x[0-9a-fA-F]+`)

					matches := re.FindAllString(criteria, -1)
					for _, match := range matches {
						// Extract the register
						parts := strings.Split(match, "=")
						reg := parts[0]
						hex_val := parts[1]

						if register, ok := BrRegToNXMMap[reg]; ok {

							// Replace the register with the corresponding value from the map
							regfileval := mapRegToFileValue(register, bridgName)
							if regfileval != "" {
								num, err := strconv.ParseUint(hex_val[2:], 16, 32)
								if err != nil {
									fmt.Println("Error:", err)
								}
								id := uint32(num)
								pol_obj := nodeIdMaps.nodeMaps[br.nodename][regfileval].id2strmap[id]
								replacement := fmt.Sprintf("%s=%s(%s)", reg, hex_val, pol_obj)
								org := fmt.Sprintf("%s=%s", reg, hex_val)
								criteria = strings.Replace(criteria, org, replacement, 1)
							}

						}
					}
					fmt.Fprintf(&buffer, "%s\n", criteria)
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
		"--", "/bin/sh", "-c", fmt.Sprintf("ovs-ofctl show %s", bridgName), "|",
		fmt.Sprintf("grep -E ' %s\\([^)]+\\):'", port)}
	log.Debugf("Running command: kubectl %s", strings.Join(cmd_args, " "))
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

func isValidPort(port int) bool {
	return port > 0 && port <= 65535
}

func protoConfigAndValidation(proto *TpProto, tcpFlag bool, tcpSrc *int, tcpDst *int, udpFlag bool, udpSrc *int,
	udpDst *int) error {
	if tcpFlag && udpFlag {
		return fmt.Errorf("\n%sInvalid Input: Either tcp or udp should be provided.%s\n", ColorRed, ColorReset)
	}

	if tcpFlag && (*udpSrc != 0 || *udpDst != 0) {
		return fmt.Errorf("\n%sInvalid Input: UDP ports are provided with TCP.%s\n", ColorRed, ColorReset)
	}

	if udpFlag && (*tcpSrc != 0 || *tcpDst != 0) {
		return fmt.Errorf("\n%sInvalid Input: TCP ports are provided with UDP.%s\n", ColorRed, ColorReset)

	}

	if tcpFlag {
		if *tcpSrc == 0 && *tcpDst == 0 {
			return fmt.Errorf("\n%sInvalid Input: If tcp is specified, either tcp_src or tcp_dst must be provided.%s\n", ColorRed, ColorReset)
		} else if *tcpSrc == 0 {
			*tcpSrc = 12345
		} else if *tcpDst == 0 {
			*tcpDst = 12345
		}

		if !isValidPort(*tcpSrc) {
			return fmt.Errorf("\n%sInvalid Input: Please enter tcp_src value in valid port range [1-65535].%s\n", ColorRed, ColorReset)

		}

		if !isValidPort(*tcpDst) {
			return fmt.Errorf("\n%sInvalid Input: Please enter tcp_dst value in valid port range [1-65535].%s\n", ColorRed, ColorReset)

		}

		proto.Enabled = true
		proto.Protocol = "tcp"
		proto.DstPort = "tcp_dst"
		proto.SrcPort = "tcp_src"
		proto.SrcPortVal = *tcpSrc
		proto.DstPortVal = *tcpDst

	} else if udpFlag {
		if *udpSrc == 0 && *udpDst == 0 {
			return fmt.Errorf("\n%sInvalid Input: If udp is specified, either udp_src or udp_dst must be provided.%s\n", ColorRed, ColorReset)
		} else if *udpSrc == 0 {
			*udpSrc = 12345
		} else if *udpDst == 0 {
			*udpDst = 12345
		}

		if !isValidPort(*udpSrc) {
			return fmt.Errorf("\n%sInvalid Input: Please enter udp_src value in valid port range [1-65535].%s\n", ColorRed, ColorReset)

		}

		if !isValidPort(*udpDst) {
			return fmt.Errorf("\n%sInvalid Input: Please enter udp_dst value in valid port range [1-65535].%s\n", ColorRed, ColorReset)

		}

		proto.Enabled = true
		proto.Protocol = "udp"
		proto.DstPort = "udp_dst"
		proto.SrcPort = "udp_src"
		proto.SrcPortVal = *udpSrc
		proto.DstPortVal = *udpDst
	}

	return nil
}

func checkDstPort(dstPod *v1.Pod, dstPort int32, protocol string) error {

	for _, container := range dstPod.Spec.Containers {
		for _, port := range container.Ports {
			if port.ContainerPort == dstPort && string(port.Protocol) == protocol {
				return nil
			}
		}
	}

	return fmt.Errorf("\n%sThe destination pod spec field does not explictly specify %s port %d%s\n", ColorYellow, protocol, dstPort, ColorReset)
}

func pod_to_pod_tracepacket(args []string, tcpFlag bool, tcpSrc int, tcpDst int, udpFlag bool, udpSrc int,
	udpDst int, verbose bool) {

	proto := &TpProto{}

	err := protoConfigAndValidation(proto, tcpFlag, &tcpSrc, &tcpDst, udpFlag, &udpSrc, &udpDst)
	if err != nil {
		fmt.Println(err)
		return
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
		err = checkDstPort(dstPod, int32(tcpDst), "TCP")
		if err != nil {
			fmt.Println(err)
		}
	} else if udpFlag {
		err = checkDstPort(dstPod, int32(udpDst), "UDP")
		if err != nil {
			fmt.Println(err)
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

	printACIDiagram()

	fmt.Printf("\n%s%s%s\n", ColorGreen, "Summary", ColorReset)

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
			if !proto.Enabled {
				cmd_args = []string{"exec", "-n", "aci-containers-system", srcOvsPodName,
					"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-access 'in_port=%s, ip, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s'", src_ep.Attributes.InterfaceName,
						srcPod.Status.PodIP, dstPod.Status.PodIP, src_ep.Mac, dst_ep.Mac)}
			} else {
				cmd_args = []string{"exec", "-n", "aci-containers-system", srcOvsPodName,
					"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-access 'in_port=%s, %s, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s,%s=%d,%s=%d'", src_ep.Attributes.InterfaceName,
						proto.Protocol, srcPod.Status.PodIP, dstPod.Status.PodIP, src_ep.Mac, dst_ep.Mac, proto.SrcPort, proto.SrcPortVal, proto.DstPort, proto.DstPortVal)}
			}
		} else {

			if !proto.Enabled {
				cmd_args = []string{"exec", "-n", "aci-containers-system", srcOvsPodName,
					"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-access 'in_port=%s, ip, "+
						"nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s'", src_ep.Attributes.InterfaceName,
						srcPod.Status.PodIP, dstPod.Status.PodIP, src_ep.Mac, "00:22:bd:f8:19:ff")}

			} else {
				cmd_args = []string{"exec", "-n", "aci-containers-system", srcOvsPodName,
					"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-access 'in_port=%s, %s, "+
						"nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s,%s=%d,%s=%d'", src_ep.Attributes.InterfaceName,
						proto.Protocol, srcPod.Status.PodIP, dstPod.Status.PodIP, src_ep.Mac, "00:22:bd:f8:19:ff", proto.SrcPort, proto.SrcPortVal, proto.DstPort, proto.DstPortVal)}
			}

		}

		log.Debugf("Running command: kubectl %s", strings.Join(cmd_args, " "))
		err = execKubectl(cmd_args, src_buffer)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return

		}

		sections = strings.Split(src_buffer.String(), "bridge")

		for idx, section := range sections {
			if strings.Contains(section, "br-access") {
				out_bridgeflows = append(out_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" + section,
					nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
			} else if strings.Contains(section, "br-int") {
				out_bridgeflows = append(out_bridgeflows, Bridge{br_type: "br-int", brFlows: "bridge" + section,
					nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
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
					fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n", ColorRed,
						"br-access", br.summary.previousTable, wrapText(brAccessTableDescriptions[br.summary.previousTable], 60), srcPod.Spec.NodeName, ColorReset)
					egresspacketdropped = true
				} else {
					fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n", ColorRed,
						"br-int", br.summary.previousTable, wrapText(brIntTableDescriptions[br.summary.previousTable], 60), srcPod.Spec.NodeName, ColorReset)
					egresspacketdropped = true
				}
			}
		}

		if !dst_pod_hostnetwork {
			if !egresspacketdropped {
				if srcPod.Spec.NodeName != dstPod.Spec.NodeName {
					fmt.Printf("%s=> Packet sent out from node:%s\n"+
						"with source_epg %s(%s)\n"+
						"to destination_epg with VXLAN_Tunnel_ID:0x%s(decimal:%d)(%s)\n"+
						"%s\n\n",
						ColorGreen, srcPod.Spec.NodeName, out_bridgeflows[len(out_bridgeflows)-1].summary.TunnelID,
						src_ep.EndpointGroupName, tun_id, tun_id_int, dst_ep.EndpointGroupName, ColorReset)
				} else {
					fmt.Printf("%s=> Packet sent out and recieved on same node: %s%s\n\n", ColorGreen,
						srcPod.Spec.NodeName, ColorReset)
				}
			}
		} else {
			if !egresspacketdropped {
				if srcPod.Spec.NodeName != dstPod.Spec.NodeName {
					fmt.Printf("%s=> Packet sent out from node:%s\n"+
						"with source_epg %s(%s)\n"+
						"to destination pod IP (%s) on the node(%s) network %s\n\n",
						ColorGreen, srcPod.Spec.NodeName, out_bridgeflows[len(out_bridgeflows)-1].summary.TunnelID,
						src_ep.EndpointGroupName, dstPod.Status.PodIP, dstPod.Spec.NodeName, ColorReset)

				} else {
					fmt.Printf("%s=> Packet sent out and recieved on same node: %s%s\n", ColorGreen, srcPod.Spec.NodeName, ColorReset)
				}
			}
		}

	} else {
		if !dst_pod_hostnetwork {
			if srcPod.Spec.NodeName != dstPod.Spec.NodeName {
				fmt.Printf("%s=> Packet sent out from source pod IP (%s) on the node(%s)\n"+
					"with node network to destination pod IP (%s) on the node(%s) %s\n",
					ColorGreen, srcPod.Status.PodIP, srcPod.Spec.NodeName, dstPod.Status.PodIP, dstPod.Spec.NodeName, ColorReset)
			} else {
				fmt.Printf("%s=> Packet sent out and recieved on same node: %s%s\n", ColorGreen, srcPod.Spec.NodeName, ColorReset)
			}
		} else {
			if srcPod.Spec.NodeName != dstPod.Spec.NodeName {
				fmt.Printf("%s=> Packet sent out from source pod IP (%s) on the node(%s)\n"+
					"with node network to destination pod IP (%s) on the node(%s) network %s\n",
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
					if !proto.Enabled {
						cmd_args = []string{"exec", "-n", "aci-containers-system", destOvsPodName,
							"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-int 'in_port=vxlan0,"+
								"tun_id=0x%s, ip, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s'",
								tun_id, srcPod.Status.PodIP, dstPod.Status.PodIP, src_ep.Mac, dst_ep.Mac)}
					} else {
						cmd_args = []string{"exec", "-n", "aci-containers-system", destOvsPodName,
							"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-int 'in_port=vxlan0,"+
								"tun_id=0x%s, %s, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s,%s=%d,%s=%d'",
								tun_id, proto.Protocol, srcPod.Status.PodIP, dstPod.Status.PodIP, src_ep.Mac,
								dst_ep.Mac, proto.SrcPort, proto.SrcPortVal, proto.DstPort, proto.DstPortVal)}
					}
				}

			} else {
				if !proto.Enabled {
					cmd_args = []string{"exec", "-n", "aci-containers-system", destOvsPodName,
						"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-int 'in_port=vxlan0,"+
							"tun_id=0x%s, ip, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s'",
							tun_id, srcPod.Status.PodIP, dstPod.Status.PodIP, "00:22:bd:f8:19:ff", dst_ep.Mac)}
				} else {
					cmd_args = []string{"exec", "-n", "aci-containers-system", destOvsPodName,
						"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-int 'in_port=vxlan0,"+
							"tun_id=0x%s, %s, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s,%s=%d,%s=%d'",
							tun_id, proto.Protocol, srcPod.Status.PodIP, dstPod.Status.PodIP, "00:22:bd:f8:19:ff",
							dst_ep.Mac, proto.SrcPort, proto.SrcPortVal, proto.DstPort, proto.DstPortVal)}
				}
			}

			log.Debugf("Running command: kubectl %s", strings.Join(cmd_args, " "))
			err = execKubectl(cmd_args, dest_buffer)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}

			sections = strings.Split(dest_buffer.String(), "bridge")

			for idx, section := range sections {
				if strings.Contains(section, "br-access") {
					in_bridgeflows = append(in_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" + section,
						nodename: dstPod.Spec.NodeName, ovsPod: destOvsPodName, opflexPod: dst_opflex_pod})
				} else if strings.Contains(section, "br-int") {
					in_bridgeflows = append(in_bridgeflows, Bridge{br_type: "br-int", brFlows: "bridge" + section,
						nodename: dstPod.Spec.NodeName, ovsPod: destOvsPodName, opflexPod: dst_opflex_pod})
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
						fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n",
							ColorRed, "br-int", br.summary.previousTable,
							wrapText(brIntTableDescriptions[br.summary.previousTable], 60), dstPod.Spec.NodeName, ColorReset)
						ingresspacketdropped = true

					} else {
						fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n",
							ColorRed, "br-access", br.summary.previousTable,
							wrapText(brAccessTableDescriptions[br.summary.previousTable], 60), dstPod.Spec.NodeName, ColorReset)
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

func getTargetPortValue(kubeClient kubernetes.Interface, service *v1.Service, dst_port int) (int32, error) {
	var targetPort intstr.IntOrString

	for _, port := range service.Spec.Ports {
		if port.Port == int32(dst_port) {
			if port.TargetPort.Type == intstr.Int {
				targetPort.IntVal = port.TargetPort.IntVal
			} else if port.TargetPort.Type == intstr.String {
				targetPort.StrVal = port.TargetPort.StrVal
			}
			break
		}
	}

	if targetPort.IntVal == 0 && targetPort.StrVal == "" {
		return 0, fmt.Errorf("No TargetPort found. Destination Port %d does not match with any Service Port\n", dst_port)

	}

	if targetPort.IntVal == 0 && targetPort.StrVal != "" {
		podList, err := kubeClient.CoreV1().Pods(service.Namespace).List(kubecontext.TODO(), metav1.ListOptions{
			LabelSelector: labels.SelectorFromSet(service.Spec.Selector).String(),
		})
		if err != nil {
			return 0, fmt.Errorf("failed to list pods: %v", err)
		}

		for _, pod := range podList.Items {
			for _, container := range pod.Spec.Containers {
				for _, port := range container.Ports {
					if port.Name == targetPort.StrVal {
						targetPort.IntVal = port.ContainerPort
						break
					}
				}
			}
		}
	}
	return targetPort.IntVal, nil
}

func pod_to_svc_tracepacket(args []string, tcpFlag bool, tcpSrc int, tcpDst int, udpFlag bool, udpSrc int,
	udpDst int, verbose bool) {

	proto := &TpProto{}

	if tcpFlag || udpFlag {
		err := protoConfigAndValidation(proto, tcpFlag, &tcpSrc, &tcpDst, udpFlag, &udpSrc, &udpDst)
		if err != nil {
			fmt.Println(err)
			return
		}
	} else {
		fmt.Printf("\n%sInvalid Input: tcp/udp protocol must be provided.%s\n", ColorRed, ColorReset)
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

	targetPort, err = getTargetPortValue(kubeClient, dest_svc, proto.DstPortVal)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
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

	printACIDiagram()

	fmt.Printf("\n%s%s%s\n", ColorGreen, "Summary", ColorReset)

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
			"--", "/bin/sh", "-c",
			fmt.Sprintf("ovs-appctl ofproto/trace br-access 'in_port=%s, %s, nw_ttl=10, nw_src=%s, nw_dst=%s, dl_src=%s, %s=%d,%s=%d'",
				src_ep.Attributes.InterfaceName, proto.Protocol,
				srcPod.Status.PodIP, dest_svc_file.ServiceMapping[0].ServiceIp, src_ep.Mac, proto.SrcPort, proto.SrcPortVal, proto.DstPort, proto.DstPortVal)}

		log.Debugf("Running command: kubectl %s", strings.Join(cmd_args, " "))
		err = execKubectl(cmd_args, src_buffer)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}

		sections := strings.Split(src_buffer.String(), "bridge")

		for idx, section := range sections {
			if strings.Contains(section, "br-access") {
				request_out_bridgeflows = append(
					request_out_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" + section,
						nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
			} else if strings.Contains(section, "br-int") {
				request_out_bridgeflows = append(
					request_out_bridgeflows, Bridge{br_type: "br-int", brFlows: "bridge" + section,
						nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
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
					fmt.Printf("\n%s%s%s\n", ColorYellow, "ForwardPath Summary", ColorReset)
					fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n\n", ColorRed,
						"br-access", br.summary.previousTable, wrapText(brAccessTableDescriptions[br.summary.previousTable],
							60), srcPod.Spec.NodeName, ColorReset)
					request_egress_packetdropped = true
				} else {
					fmt.Printf("\n%s%s%s\n", ColorYellow, "ForwardPath Summary", ColorReset)
					fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n\n", ColorRed,
						"br-int", br.summary.previousTable, wrapText(brIntTableDescriptions[br.summary.previousTable], 60),
						srcPod.Spec.NodeName, ColorReset)
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
						fmt.Printf("\n%s%s%s\n", ColorYellow, "ForwardPath Summary", ColorReset)

						fmt.Printf("%s=> Packet sent out from node:%s\n"+
							"with source_epg %s(%s)\n"+
							"to destination service IP %s which translates to endpoint %s(IP->%s)\n"+
							"with destination_epg/VXLAN_Tunnel_ID:0x%s(decimal:%d)(%s) %s\n\n",
							ColorGreen, srcPod.Spec.NodeName, request_out_bridgeflows[len(request_out_bridgeflows)-1].summary.TunnelID,
							src_ep.EndpointGroupName, dest_svc.Spec.ClusterIP, destPod.Name, destPod.Status.PodIP, tun_id,
							tun_id_int, dest_ep.EndpointGroupName, ColorReset)

					} else {
						fmt.Printf("\n%s%s%s\n", ColorYellow, "ForwardPath Summary", ColorReset)
						fmt.Printf("%s=> Packet sent out to destination service IP %s\n"+
							"which translates to endpoint %s(IP->%s)\n"+
							"and received on the same node: %s %s\n\n",
							ColorGreen, dest_svc.Spec.ClusterIP, destPod.Name, destPod.Status.PodIP, srcPod.Spec.NodeName, ColorReset)

					}
				} else {
					if srcPod.Spec.NodeName != destPod.Spec.NodeName {
						fmt.Printf("\n%s%s%s\n", ColorYellow, "ForwardPath Summary", ColorReset)
						fmt.Printf("%s=> Packet sent out from node:%s\n"+
							"with source_epg %s(%s)\n"+
							"to destination service IP %s\n"+
							"with endpoint IP:%s on node(%s) network%s\n\n",
							ColorGreen, srcPod.Spec.NodeName, request_out_bridgeflows[len(request_out_bridgeflows)-1].summary.TunnelID,
							src_ep.EndpointGroupName, dest_svc.Spec.ClusterIP, destPod.Status.PodIP, dst_node.Name, ColorReset)

					} else {
						fmt.Printf("\n%s%s%s\n", ColorYellow, "ForwardPath Summary", ColorReset)
						fmt.Printf("%s=> Packet sent out to destination service IP %s\n"+
							"which translates to endpoint %s(IP->%s)\n"+
							"and received on the same node: %s %s\n\n",
							ColorGreen, dest_svc.Spec.ClusterIP, destPod.Name, destPod.Status.PodIP, srcPod.Spec.NodeName, ColorReset)

					}
				}

			} else {
				fmt.Printf("\n%s%s%s\n", ColorYellow, "ForwardPath Summary", ColorReset)
				fmt.Printf("%s=> Packet sent out from node:%s with source_epg %s(%s) to destination service ip %s"+
					" with endpoint IP:%s on node network%s\n\n",
					ColorGreen, srcPod.Spec.NodeName, request_out_bridgeflows[len(request_out_bridgeflows)-1].summary.TunnelID,
					src_ep.EndpointGroupName, dest_svc.Spec.ClusterIP, destPodIp, ColorReset)
			}

		}

	} else {
		fmt.Printf("\n%s%s%s\n", ColorYellow, "ForwardPath Summary", ColorReset)
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
					"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-int 'in_port=vxlan0,"+
						"tun_id=0x%s, %s,nw_ttl=10, nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s,%s=%d,%s=%d'",
						tun_id, proto.Protocol, srcPod.Status.PodIP, destPod.Status.PodIP, "00:22:bd:f8:19:ff",
						dest_ep.Mac, proto.SrcPort, tcpSrc, proto.DstPort, targetPort)}

				log.Debugf("Running command: kubectl %s", strings.Join(cmd_args, " "))
				err = execKubectl(cmd_args, dest_buffer)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					return
				}

				sections := strings.Split(dest_buffer.String(), "bridge")

				for idx, section := range sections {
					if strings.Contains(section, "br-access") {
						request_in_bridgeflows = append(request_in_bridgeflows, Bridge{br_type: "br-access",
							brFlows: "bridge" + section, nodename: destPod.Spec.NodeName, ovsPod: destOvsPodName,
							opflexPod: dst_opflex_pod})
					} else if strings.Contains(section, "br-int") {
						request_in_bridgeflows = append(request_in_bridgeflows, Bridge{br_type: "br-int",
							brFlows: "bridge" + section, nodename: destPod.Spec.NodeName, ovsPod: destOvsPodName,
							opflexPod: dst_opflex_pod})
					}

					if idx > 0 && strings.Contains(sections[idx-1], "br-access") && strings.Contains(sections[idx-1],
						"resume conntrack") {
						request_in_bridgeflows[len(request_in_bridgeflows)-1].br_type = "br-access"
					}

					if idx > 0 && strings.Contains(sections[idx-1], "br-int") && strings.Contains(sections[idx-1],
						"resume conntrack") {
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
							fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n\n",
								ColorRed, "br-int", br.summary.previousTable, wrapText(brIntTableDescriptions[br.summary.previousTable],
									60), destPod.Spec.NodeName, ColorReset)
							request_ingress_packetdropped = true

						} else {
							fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n\n",
								ColorRed, "br-access", br.summary.previousTable, wrapText(brAccessTableDescriptions[br.summary.previousTable],
									60), destPod.Spec.NodeName, ColorReset)
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
							"%s=> No ovs datapath found for the request packet at the destination\n"+
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
							"%s=> No ovs datapath found for the request packet at the destination\n"+
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
				"%s=> No ovs datapath found for the request packet at the destination\n"+
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
		fmt.Printf("\n\n%s%s%s\n\n", ColorYellow, "ReturnPath Summary", ColorReset)
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
					"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-access 'in_port=%s, %s, "+
						"nw_ttl=10,nw_src=%s, nw_dst=%s, dl_src=%s, dl_dst=%s,%s=%d,%s=%d'",
						dest_ep.Attributes.InterfaceName, proto.Protocol,
						destPod.Status.PodIP, srcPod.Status.PodIP, dest_ep.Mac,
						"00:22:bd:f8:19:ff", proto.DstPort, targetPort, proto.SrcPort, tcpSrc)}

				log.Debugf("Running command: kubectl %s", strings.Join(cmd_args, " "))
				err = execKubectl(cmd_args, src_buffer)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					return

				}

				sections := strings.Split(src_buffer.String(), "bridge")

				for idx, section := range sections {
					if strings.Contains(section, "br-access") {
						reply_out_bridgeflows = append(reply_out_bridgeflows, Bridge{br_type: "br-access",
							brFlows: "bridge" + section, nodename: destPod.Spec.NodeName, ovsPod: destOvsPodName,
							opflexPod: dst_opflex_pod})
					} else if strings.Contains(section, "br-int") {
						reply_out_bridgeflows = append(reply_out_bridgeflows, Bridge{br_type: "br-int",
							brFlows: "bridge" + section, nodename: destPod.Spec.NodeName, ovsPod: destOvsPodName,
							opflexPod: dst_opflex_pod})
					}

					if idx > 0 && strings.Contains(sections[idx-1], "br-access") &&
						strings.Contains(sections[idx-1], "resume conntrack") {
						reply_out_bridgeflows[len(reply_out_bridgeflows)-1].br_type = "br-access"
					}

					if idx > 0 && strings.Contains(sections[idx-1], "br-int") &&
						strings.Contains(sections[idx-1], "resume conntrack") {
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
							fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n\n",
								ColorRed, "br-access", br.summary.previousTable,
								wrapText(brAccessTableDescriptions[br.summary.previousTable], 60),
								destPod.Spec.NodeName, ColorReset)
							reply_egress_packetdropped = true
						} else {
							fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n\n",
								ColorRed, "br-int", br.summary.previousTable,
								wrapText(brIntTableDescriptions[br.summary.previousTable], 60),
								destPod.Spec.NodeName, ColorReset)
							reply_egress_packetdropped = true
						}
					}
				}

				if !reply_egress_packetdropped {
					if !src_pod_hostnetwork {
						fmt.Printf("%s=> Packet sent out from node:%s\n"+
							"with epg %s(%s)\n"+
							"to origin pod IP %s\n"+
							"with destination_epg/VXLAN_Tunnel_ID:0x%s(decimal:%d)(%s) %s\n\n",
							ColorGreen, destPod.Spec.NodeName, reply_out_bridgeflows[len(request_out_bridgeflows)-1].summary.TunnelID,
							dest_ep.EndpointGroupName, srcPod.Status.PodIP, tun_id, tun_id_int, src_ep.EndpointGroupName, ColorReset)

					} else {
						fmt.Printf("%s=> Packet sent out from node:%s\n"+
							"with epg %s(%s)\n"+
							"to origin pod IP %s\n"+
							"on node(%s) network %s\n\n",
							ColorGreen, destPod.Spec.NodeName, reply_out_bridgeflows[len(request_out_bridgeflows)-1].summary.TunnelID,
							dest_ep.EndpointGroupName, srcPod.Status.PodIP, src_node.Name, ColorReset)
					}
				}
			}
		} else {
			if !src_pod_hostnetwork {
				fmt.Printf(
					"%s=> No ovs datapath found for the reply packet\n"+
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
					"%s=> No ovs datapath found for the reply packet\n"+
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
						"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-int 'in_port=vxlan0,tun_id=0x%s, "+
							"%s,ct_state=trk|est,ct_mark=%s,nw_src=%s, nw_dst=%s,dl_dst=%s,%s=%d,nw_ttl=64'",
							tun_id, proto.Protocol, ct_mark, destPod.Status.PodIP, srcPod.Status.PodIP, src_ep.Mac, proto.SrcPort, targetPort)}

					log.Debugf("Running command: kubectl %s", strings.Join(cmd_args, " "))
					err = execKubectl(cmd_args, dest_buffer)
					if err != nil {
						fmt.Fprintln(os.Stderr, err)
						return

					}
				}

			} else {
				cmd_args = []string{"exec", "-n", "aci-containers-system", srcOvsPodName,
					"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-int 'in_port=vxlan0,tun_id=0x%s, "+
						"%s,ct_state=trk|est,ct_mark=%s,nw_src=%s, nw_dst=%s,dl_dst=%s,%s=%d,nw_ttl=64'",
						tun_id, proto.Protocol, ct_mark, destPodIp, srcPod.Status.PodIP, src_ep.Mac, proto.SrcPort, targetPort)}

				log.Debugf("Running command: kubectl %s", strings.Join(cmd_args, " "))
				err = execKubectl(cmd_args, dest_buffer)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					return

				}

			}

			sections := strings.Split(dest_buffer.String(), "bridge")

			for idx, section := range sections {
				if strings.Contains(section, "br-access") {
					reply_in_bridgeflows = append(reply_in_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" +
						section, nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
				} else if strings.Contains(section, "br-int") {
					reply_in_bridgeflows = append(reply_in_bridgeflows, Bridge{br_type: "br-int", brFlows: "bridge" +
						section, nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
				}

				if idx > 0 && strings.Contains(sections[idx-1], "br-access") &&
					strings.Contains(sections[idx-1], "resume conntrack") {
					reply_in_bridgeflows[len(reply_in_bridgeflows)-1].br_type = "br-access"
				}

				if idx > 0 && strings.Contains(sections[idx-1], "br-int") &&
					strings.Contains(sections[idx-1], "resume conntrack") {
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
						fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n\n",
							ColorRed, "br-access", br.summary.previousTable,
							wrapText(brAccessTableDescriptions[br.summary.previousTable], 60),
							srcPod.Spec.NodeName, ColorReset)
						reply_ingress_packetdropped = true
					} else {
						fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n\n",
							ColorRed, "br-int",
							br.summary.previousTable, wrapText(brIntTableDescriptions[br.summary.previousTable], 60),
							srcPod.Spec.NodeName, ColorReset)
						reply_ingress_packetdropped = true
					}
				}
			}

			if !reply_ingress_packetdropped {
				fmt.Printf("%s=> Packet recieved on the source Pod %s(%s) %s\n\n", ColorGreen,
					srcPod.Name, srcPod.Status.PodIP, ColorReset)
			}
		}
	}

	if verbose {
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

		if !dst_pod_hostnetwork && !request_egress_packetdropped && !request_ingress_packetdropped && destPod != nil &&
			srcPod.Spec.NodeName != destPod.Spec.NodeName {
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

		if !src_pod_hostnetwork && !request_egress_packetdropped && !request_ingress_packetdropped &&
			!reply_egress_packetdropped && ((destPod != nil && srcPod.Spec.NodeName != destPod.Spec.NodeName) ||
			(destPodIp != "" && destNodeName != "" && src_node.Name != destNodeName)) {
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

func pod_to_ext_tracepacket(args []string, tcpFlag bool, tcpSrc int, tcpDst int, udpFlag bool, udpSrc int,
	udpDst int, verbose bool) {

	proto := &TpProto{}

	if tcpFlag || udpFlag {
		err := protoConfigAndValidation(proto, tcpFlag, &tcpSrc, &tcpDst, udpFlag, &udpSrc, &udpDst)
		if err != nil {
			fmt.Println(err)
			return
		}
	} else {
		fmt.Printf("\n%sInvalid Input: tcp/udp protocol must be provided.%s\n", ColorRed, ColorReset)
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
		fmt.Fprintf(os.Stderr, "\n%sCould not track OVS datapath as pod(%s) is on the node(%s) network(%s)%s\n",
			ColorRed, srcPod.Name, src_node.Name, srcPod.Status.PodIP, ColorReset)
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

	cmd_args := []string{"exec", "-n", "aci-containers-system", srcOvsPodName,
		"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-access 'in_port=%s, %s, nw_ttl=10, "+
			"nw_src=%s, nw_dst=%s, dl_src=%s, %s=%d,%s=%d'", src_ep.Attributes.InterfaceName,
			proto.Protocol, srcPod.Status.PodIP, destip, src_ep.Mac, proto.SrcPort, tcpSrc, proto.DstPort, tcpDst)}

	log.Debugf("Running command: kubectl %s", strings.Join(cmd_args, " "))
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
			out_bridgeflows = append(out_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" + section,
				nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
		} else if strings.Contains(section, "br-int") {
			out_bridgeflows = append(out_bridgeflows, Bridge{br_type: "br-int", brFlows: "bridge" + section,
				nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
		}

		if idx > 0 && strings.Contains(sections[idx-1], "br-access") && strings.Contains(sections[idx-1], "resume conntrack") {
			out_bridgeflows[len(out_bridgeflows)-1].br_type = "br-access"
		}

		if idx > 0 && strings.Contains(sections[idx-1], "br-int") && strings.Contains(sections[idx-1], "resume conntrack") {
			out_bridgeflows[len(out_bridgeflows)-1].br_type = "br-int"
		}
	}

	for idx := range out_bridgeflows {
		out_bridgeflows[idx].brFlowEntries = out_bridgeflows[idx].parseFlowEntries()
		out_bridgeflows[idx].out_br_buff = out_bridgeflows[idx].buildPacketTrace()
	}

	var outPacketDropped bool
	var tun_id string

	printACIDiagram()

	fmt.Printf("\n%s%s%s\n", ColorGreen, "Summary", ColorReset)

	// Print the EP details
	printEndpointDetails(src_ep, srcPod, src_opflex_pod)

	fmt.Printf("\n\n%s%s%s\n\n", ColorYellow, "ForwardPath Summary", ColorReset)
	for _, br := range out_bridgeflows {
		if br.summary != nil && br.summary.PacketDropped {
			if br.br_type == "br-access" {
				fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n", ColorRed,
					"br-access", br.summary.previousTable,
					wrapText(brAccessTableDescriptions[br.summary.previousTable], 60), srcPod.Spec.NodeName, ColorReset)
				outPacketDropped = true
			} else {
				fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n", ColorRed, "br-int",
					br.summary.previousTable,
					wrapText(brIntTableDescriptions[br.summary.previousTable], 60), srcPod.Spec.NodeName, ColorReset)
				outPacketDropped = true
			}
		}
	}

	if !outPacketDropped {
		tun_id = out_bridgeflows[len(out_bridgeflows)-1].summary.TunnelID
		if out_bridgeflows[len(out_bridgeflows)-1].summary.snat_ip != "" {
			fmt.Printf("%s=> Packet sent out from node:%s with source_epg %s(%s) with snat_ip %s to the destination %s:%d %s\n",
				ColorGreen, srcPod.Spec.NodeName, tun_id, src_ep.EndpointGroupName,
				out_bridgeflows[len(out_bridgeflows)-1].summary.snat_ip, destip, tcpDst, ColorReset)
		} else {
			fmt.Printf("%s=> Packet sent out from node:%s with source_epg %s(%s) to the destination %s:%d %s\n",
				ColorGreen, srcPod.Spec.NodeName, tun_id, src_ep.EndpointGroupName, destip, tcpDst, ColorReset)
		}
	}

	/////////////////////////// Reply Path ///////////////////////
	in_bridgeflows := []Bridge{}
	dest_buffer := new(bytes.Buffer)
	var inPacketDropped bool

	if !outPacketDropped {
		fmt.Printf("\n\n%s%s%s\n\n", ColorYellow, "ReturnPath Summary", ColorReset)

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

		cmd_args = []string{"exec", "-n", "aci-containers-system", srcOvsPodName,
			"--", "/bin/sh", "-c", fmt.Sprintf("ovs-appctl ofproto/trace br-int 'in_port=vxlan0,tun_id=0x%s, "+
				"%s,nw_src=%s, nw_dst=%s,dl_dst=%s,%s=%d,nw_ttl=64' --ct-next rpl,est,trk",
				tun_id, proto.Protocol, destip, srcPod.Status.PodIP, src_ep.Mac, proto.SrcPort, tcpDst)}

		log.Debugf("Running command: kubectl %s", strings.Join(cmd_args, " "))
		err = execKubectl(cmd_args, dest_buffer)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		sections := strings.Split(dest_buffer.String(), "bridge")

		for idx, section := range sections {
			if strings.Contains(section, "br-access") {
				in_bridgeflows = append(in_bridgeflows, Bridge{br_type: "br-access", brFlows: "bridge" +
					section, nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
			} else if strings.Contains(section, "br-int") {
				in_bridgeflows = append(in_bridgeflows, Bridge{br_type: "br-int", brFlows: "bridge" +
					section, nodename: srcPod.Spec.NodeName, ovsPod: srcOvsPodName, opflexPod: src_opflex_pod})
			}

			if idx > 0 && strings.Contains(sections[idx-1], "br-access") &&
				strings.Contains(sections[idx-1], "resume conntrack") {
				in_bridgeflows[len(in_bridgeflows)-1].br_type = "br-access"
			}

			if idx > 0 && strings.Contains(sections[idx-1], "br-int") &&
				strings.Contains(sections[idx-1], "resume conntrack") {
				in_bridgeflows[len(in_bridgeflows)-1].br_type = "br-int"
			}
		}

		for idx := range in_bridgeflows {
			in_bridgeflows[idx].brFlowEntries = in_bridgeflows[idx].parseFlowEntries()
			in_bridgeflows[idx].out_br_buff = in_bridgeflows[idx].buildPacketTrace()
		}

		for _, br := range in_bridgeflows {
			if br.summary != nil && br.summary.PacketDropped {
				if br.br_type == "br-access" {
					fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n\n",
						ColorRed, "br-access", br.summary.previousTable,
						wrapText(brAccessTableDescriptions[br.summary.previousTable], 60),
						srcPod.Spec.NodeName, ColorReset)
					inPacketDropped = true
				} else {
					fmt.Printf("%s=> Packet dropped on bridge: %s and in table%d: %s on node: %s%s\n\n",
						ColorRed, "br-int",
						br.summary.previousTable, wrapText(brIntTableDescriptions[br.summary.previousTable], 60),
						srcPod.Spec.NodeName, ColorReset)
					inPacketDropped = true
				}
			}
		}

		if len(in_bridgeflows) != 0 && !inPacketDropped {
			fmt.Printf("%s=> Packet received on the source Pod %s(%s) of node:%s with TunID: %s%s\n",
				ColorGreen, srcPod.Name, srcPod.Status.PodIP, srcPod.Spec.NodeName, tun_id, ColorReset)
		}
	}

	if verbose {
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
		if !outPacketDropped {
			fmt.Printf("\n\n%s%s%s%s\n", ColorGreen, "ReturnPath Incoming Packet to node: ", src_node.Name, ColorReset)
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
}

// FetchFileContent fetches the content of the file from the pod
func FetchFileContent(opflex_pod_name, filePath string) ([]byte, error) {
	file_buffer := new(bytes.Buffer)
	cmd_args := []string{"exec", "-n", "aci-containers-system", opflex_pod_name, "-c", "opflex-agent",
		"--", "/bin/sh", "-c", fmt.Sprintf("cat %s", filePath)}

	log.Debugf("Running command: kubectl %s", strings.Join(cmd_args, " "))
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

	log.Debugf("Running command: kubectl %s", strings.Join(cmd_args, " "))
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

	log.Debugf("Running command: kubectl %s", strings.Join(cmd_args, " "))
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
	fmt.Fprintf(w, "%sIP:\t%v\n", ColorGreen, ep.Ip)
	fmt.Fprintf(w, "%sMAC Address:\t%s\n", ColorGreen, ep.Mac)
	fmt.Fprintf(w, "%sAccess Interface:\t%s\n", ColorGreen, ep.AccessInterface)
	fmt.Fprintf(w, "%sAccess Uplink Interface:\t%s\n", ColorGreen, ep.AccessUplinkInterface)
	fmt.Fprintf(w, "%sInterface Name:\t%s\n", ColorGreen, ep.InterfaceName)
	fmt.Fprintf(w, "%sNamespace:\t%s\n", ColorGreen, ep.Attributes.Namespace)
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
	cmd_args := []string{"exec", "-n", "aci-containers-system", hostPodName, "-c", "opflex-agent", "--", "/bin/sh", "-c", "gbp_inspect -fprq DmtreeRoot -t dump"}

	log.Debugf("Running command: kubectl %s", strings.Join(cmd_args, " "))
	err = execKubectl(cmd_args, gbpBuffer)
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
	yellow := "\033[33m"
	reset := "\033[0m"
	fmt.Println(yellow)
	fmt.Print("\nTracing packet flow...\n")
	fmt.Print(`
             K8s-Node            
+-------------------------------+
|         +-----------+         |
|         | K8s-Pod-A |         |
|         +-----+-----+         |
|           veth|               |
|         +-----+-----+         |
|         | br-access |         |
|         +-----+-----+         |
|        pa-veth|               |
|               |pi-veth        |
|          +----+-----+         |
|          |  br-int  |         |
|          +----+-----+         |
|  br-int_vxlan0|               |
|               |vxlan_sys_8472 |
| ethX.InfraVLAN|               |
|            +--+---+           |
|            | ethX |           |
+--------------+----------------+
               |  ^              
               v  |              
           +------+---+          
           |  Switch  |          
           +----------+          
`)
	fmt.Println(reset)

}

var PodtoPodtraceCmd = &cobra.Command{
	Use:     "trace_pod_to_pod [src_ns:src_pod] [dest_ns:dest_pod]",
	Short:   "Trace ip packet's flow in ovs for pod to pod communication",
	Example: `acikubectl trace_pod_to_pod src_ns:src_pod dest_ns:dest_pod`,
	Args:    cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		pod_to_pod_tracepacket(args, tcpFlag, tcpSrc, tcpDst, udpFlag, udpSrc, udpDst, verbose)
	},
}

var PodtoSvctraceCmd = &cobra.Command{
	Use:     "trace_pod_to_svc [src_ns:src_pod] [dest_ns:dest_svc]",
	Short:   "Trace ip packet's flow in ovs from pod to service communication",
	Example: `acikubectl trace_pod_to_svc src_ns:src_pod dest_ns:dest_svc`,
	Args:    cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		pod_to_svc_tracepacket(args, tcpFlag, tcpSrc, tcpDst, udpFlag, udpSrc, udpDst, verbose)
	},
}

var PodtoExttraceCmd = &cobra.Command{
	Use:     "trace_pod_to_ext [src_ns:src_pod] [dest_ip]",
	Short:   "Trace ip packet's flow in ovs from pod to outside cluster communication",
	Example: `acikubectl trace_pod_to_ext src_ns:src_pod dest_ip`,
	Args:    cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		pod_to_ext_tracepacket(args, tcpFlag, tcpSrc, tcpDst, udpFlag, udpSrc, udpDst, verbose)
	},
}

var nodeIdMaps *NodeIdMaps
var tcpFlag, udpFlag bool
var tcpSrc, udpSrc int
var tcpDst, udpDst int
var verbose bool
var ct_mark string

func init() {
	initLogger()
	nodeIdMaps = NewNodeIdMaps()

	PodtoPodtraceCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	PodtoPodtraceCmd.Flags().BoolVar(&tcpFlag, "tcp", false, "Specify if the protocol is TCP")
	PodtoPodtraceCmd.Flags().IntVar(&tcpSrc, "tcp_src", 0, "Specify the source TCP port")
	PodtoPodtraceCmd.Flags().IntVar(&tcpDst, "tcp_dst", 0, "Specify the destination TCP port")
	PodtoPodtraceCmd.Flags().BoolVar(&udpFlag, "udp", false, "Specify if the protocol is UDP")
	PodtoPodtraceCmd.Flags().IntVar(&udpSrc, "udp_src", 0, "Specify the source UDP port")
	PodtoPodtraceCmd.Flags().IntVar(&udpDst, "udp_dst", 0, "Specify the destination UDP port")

	PodtoSvctraceCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	PodtoSvctraceCmd.Flags().BoolVar(&tcpFlag, "tcp", false, "Specify if the protocol is TCP")
	PodtoSvctraceCmd.Flags().IntVar(&tcpSrc, "tcp_src", 0, "Specify the source TCP port")
	PodtoSvctraceCmd.Flags().IntVar(&tcpDst, "tcp_dst", 0, "Specify the destination TCP port")
	PodtoSvctraceCmd.Flags().BoolVar(&udpFlag, "udp", false, "Specify if the protocol is UDP")
	PodtoSvctraceCmd.Flags().IntVar(&udpSrc, "udp_src", 0, "Specify the source UDP port")
	PodtoSvctraceCmd.Flags().IntVar(&udpDst, "udp_dst", 0, "Specify the destination UDP port")

	PodtoExttraceCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	PodtoExttraceCmd.Flags().BoolVar(&tcpFlag, "tcp", false, "Specify if the protocol is TCP")
	PodtoExttraceCmd.Flags().IntVar(&tcpSrc, "tcp_src", 0, "Specify the source TCP port")
	PodtoExttraceCmd.Flags().IntVar(&tcpDst, "tcp_dst", 0, "Specify the destination TCP port")
	PodtoExttraceCmd.Flags().BoolVar(&udpFlag, "udp", false, "Specify if the protocol is UDP")
	PodtoExttraceCmd.Flags().IntVar(&udpSrc, "udp_src", 0, "Specify the source UDP port")
	PodtoExttraceCmd.Flags().IntVar(&udpDst, "udp_dst", 0, "Specify the destination UDP port")

	RootCmd.AddCommand(PodtoPodtraceCmd)
	RootCmd.AddCommand(PodtoSvctraceCmd)
	RootCmd.AddCommand(PodtoExttraceCmd)
}

package hostagent

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type LLDPInterfaceState struct {
	Enabled       bool
	InterfaceType string
	AdminState    string
}

type FabricDiscoveryAgentLLDPNMState struct {
	hostAgent       *HostAgent
	indexMutex      sync.Mutex
	collectTrigger  chan bool
	LLDPIntfMap     map[string]*LLDPInterfaceState
	LLDPNeighborMap map[string]map[string][]FabricAttachmentData
	port2BridgeMap  map[string]string
	bridge2PortsMap map[string]map[string]bool
	port2BondMap    map[string]string
	bond2PortsMap   map[string]map[string]bool
}

func (agent *FabricDiscoveryAgentLLDPNMState) RunCommand(cmd string, cmdArgs ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, cmd, cmdArgs...)
	return command.Output()
}

func (agent *FabricDiscoveryAgentLLDPNMState) Init(ha *HostAgent) error {
	agent.hostAgent = ha
	agent.collectTrigger = make(chan bool)
	agent.LLDPIntfMap = make(map[string]*LLDPInterfaceState)
	agent.LLDPNeighborMap = make(map[string]map[string][]FabricAttachmentData)
	agent.port2BridgeMap = make(map[string]string)
	agent.bridge2PortsMap = make(map[string]map[string]bool)
	agent.port2BondMap = make(map[string]string)
	agent.bond2PortsMap = make(map[string]map[string]bool)
	if ha.integ_test == nil {
		_, err := agent.RunCommand("nmstatectl", "show")
		return err
	} else {
		return nil
	}
}

func (agent *FabricDiscoveryAgentLLDPNMState) PopulateAdjacencies(adjs map[string][]FabricAttachmentData) {
	agent.indexMutex.Lock()
	for iface, adj := range adjs {
		if _, ok := agent.LLDPNeighborMap[iface]; !ok {
			agent.LLDPNeighborMap[iface] = make(map[string][]FabricAttachmentData)
		}
		for _, fabAtt := range adj {
			agent.LLDPNeighborMap[iface][fabAtt.SystemName] = append(agent.LLDPNeighborMap[iface][fabAtt.SystemName], fabAtt)
		}
	}
	agent.indexMutex.Unlock()
}

func (agent *FabricDiscoveryAgentLLDPNMState) TriggerCollectionDiscoveryData() {
	agent.collectTrigger <- true
}

func (agent *FabricDiscoveryAgentLLDPNMState) getBondAdjacencyLocked(bond string, adj []*FabricAttachmentData) []*FabricAttachmentData {
	for port := range agent.bond2PortsMap[bond] {
		for sys := range agent.LLDPNeighborMap[port] {
			for link := range agent.LLDPNeighborMap[port][sys] {
				adj = append(adj, &agent.LLDPNeighborMap[port][sys][link])
			}
		}
	}
	return adj
}

func (agent *FabricDiscoveryAgentLLDPNMState) notifyBridge(bridge string) {
	adj := []*FabricAttachmentData{}
	agent.indexMutex.Lock()
	for port := range agent.bridge2PortsMap[bridge] {
		if _, ok := agent.bond2PortsMap[port]; ok {
			adj = agent.getBondAdjacencyLocked(port, adj)
			continue
		}
		for sys := range agent.LLDPNeighborMap[port] {
			for link := range agent.LLDPNeighborMap[port][sys] {
				adj = append(adj, &agent.LLDPNeighborMap[port][sys][link])
			}
		}
	}
	agent.indexMutex.Unlock()
	agent.hostAgent.log.Infof("Collecting for bridge: %s", bridge)
	agent.hostAgent.NotifyFabricAdjacency(bridge, adj)
}

func (agent *FabricDiscoveryAgentLLDPNMState) notifyBond(bond string) {
	adj := []*FabricAttachmentData{}
	agent.indexMutex.Lock()
	if bridge, ok := agent.port2BridgeMap[bond]; ok {
		agent.indexMutex.Unlock()
		agent.notifyBridge(bridge)
		return
	}
	adj = agent.getBondAdjacencyLocked(bond, adj)
	agent.indexMutex.Unlock()
	agent.hostAgent.log.Infof("Collecting for bond: %s", bond)
	agent.hostAgent.NotifyFabricAdjacency(bond, adj)
}

func (agent *FabricDiscoveryAgentLLDPNMState) CollectDiscoveryData(stopCh <-chan struct{}) {
	if agent.hostAgent.integ_test != nil {
		return
	}
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		agent.hostAgent.log.Debugf("Starting FabricDiscoveryAgentLLDPNMState")
		for {
			select {
			case <-stopCh:
				return
			case <-agent.collectTrigger:
			case <-ticker.C:
				//Scan for new interfaces
				if agent.hostAgent.integ_test != nil {
					continue
				}
				out, err := agent.RunCommand("nmstatectl", "show", "--json")
				if err != nil {
					agent.hostAgent.log.Errorf("nmstatectl failed:%v", err)
					continue
				}
				var base interface{}
				if err := json.Unmarshal(out, &base); err != nil {
					agent.hostAgent.log.Errorf("unmarshaling  %v", err)
					continue
				}
				visited := map[string]bool{}
				nmOut := base.(map[string]interface{})
				nmOutInterfaces := nmOut["interfaces"].([]interface{})
				for _, intf := range nmOutInterfaces {
					intfData := intf.(map[string]interface{})
					lldpData, ok := intfData["lldp"].(map[string]interface{})
					lldpEnabled := false
					if ok {
						lldpEnabled = lldpData["enabled"].(bool)
					}
					iface := intfData["name"].(string)
					visited[iface] = true
					agent.indexMutex.Lock()
					agent.LLDPIntfMap[iface] = &LLDPInterfaceState{
						Enabled:       lldpEnabled,
						InterfaceType: intfData["type"].(string),
						AdminState:    intfData["state"].(string),
					}
					bridgeNotify := false
					bondNotify := false
					isCompositeIf := false
					var bridge, ifaceStr, bond string
					if agent.LLDPIntfMap[iface].InterfaceType == "linux-bridge" {
						if bridgeData, ok := intfData["bridge"].(map[string]interface{}); ok {
							if bridgePorts, ok := bridgeData["port"].([]interface{}); ok {
								bridgeMbrs := make(map[string]bool)
								for _, bridgePortData := range bridgePorts {
									bridgePort := bridgePortData.(map[string]interface{})
									if port, ok := bridgePort["name"].(string); ok {
										agent.port2BridgeMap[port] = iface
										bridgeMbrs[port] = true
										if _, ok := agent.bridge2PortsMap[iface]; !ok {
											bridgeNotify = true
										} else if _, ok := agent.bridge2PortsMap[iface][port]; !ok {
											bridgeNotify = true
										}
									}
								}
								for currPort := range agent.bridge2PortsMap[iface] {
									if _, ok := bridgeMbrs[currPort]; !ok {
										delete(agent.port2BridgeMap, currPort)
										bridgeNotify = true
									}
								}
								agent.bridge2PortsMap[iface] = bridgeMbrs
							}
						}
						bridge = iface
						isCompositeIf = true
					} else if agent.LLDPIntfMap[iface].InterfaceType == "bond" {

						if aggData, ok := intfData["link-aggregation"].(map[string]interface{}); ok {
							if portList, ok := aggData["port"].([]interface{}); ok {
								portMap := make(map[string]bool)
								for _, portData := range portList {
									if port, ok := portData.(string); ok {
										portMap[port] = true
										agent.port2BondMap[port] = iface
										if _, ok := agent.bond2PortsMap[iface]; !ok {
											bondNotify = true
										} else if _, ok := agent.bond2PortsMap[iface][port]; !ok {
											bondNotify = true
										}
									}
								}
								for currPort := range agent.bond2PortsMap[iface] {
									if _, ok := portMap[currPort]; !ok {
										delete(agent.port2BondMap, currPort)
										bondNotify = true
									}
								}
								agent.bond2PortsMap[iface] = portMap
							}
						}
						bond = iface
						isCompositeIf = true
					} else {
						if bridge, ok = agent.port2BridgeMap[iface]; !ok {
							bridge = "default"
						}
						if bridge != "default" {
							ifaceStr = "bridge " + bridge + "iface " + iface
						} else {
							ifaceStr = "iface " + iface
						}
						if bond, ok = agent.port2BondMap[iface]; !ok {
							bond = ""
						}
					}
					agent.indexMutex.Unlock()
					if lldpEnabled && !isCompositeIf {
						needNotify := false
						nbrList, ok := lldpData["neighbors"].([]interface{})
						if !ok {
							continue
						}
						for _, neighbor := range nbrList {
							nbrtlvs := neighbor.([]interface{})
							var fabricAtt FabricAttachmentData
							for _, nbrtlv := range nbrtlvs {
								tlv := nbrtlv.(map[string]interface{})
								if tlv_type_val, ok := tlv["type"]; ok {
									tlv_type := tlv_type_val.(float64)
									switch tlv_type {
									case 2:
										remoteIntf := "/pathep-[" + strings.ToLower(tlv["port-id"].(string)) + "]"
										fabricAtt.StaticPath += remoteIntf
									case 6:
										fabricAtt.StaticPath = tlv["system-description"].(string) +
											fabricAtt.StaticPath
									case 5:
										fabricAtt.SystemName = tlv["system-name"].(string)
									}
								}
							}
							if !strings.Contains(fabricAtt.StaticPath, "topology") || !strings.Contains(fabricAtt.StaticPath, "pod") || !strings.Contains(fabricAtt.StaticPath, "node") {
								agent.hostAgent.log.Debugf("Skipping invalid staticpath from non-ACI neighbor:%s", fabricAtt.StaticPath)
								continue
							}
							agent.indexMutex.Lock()
							existingNeighbors, ok := agent.LLDPNeighborMap[iface]
							if ok {
								if existingNeighbor, ok := existingNeighbors[fabricAtt.SystemName]; ok {
									existingLink := false
									for _, currLink := range existingNeighbor {
										if currLink.StaticPath == fabricAtt.StaticPath {
											existingLink = true
											break
										}
									}
									if !existingLink {
										agent.LLDPNeighborMap[iface][fabricAtt.SystemName] = append(agent.LLDPNeighborMap[iface][fabricAtt.SystemName], fabricAtt)
										agent.hostAgent.log.Infof("LLDP Adjacency updated for %s: %s", ifaceStr, fabricAtt.StaticPath)
										needNotify = true
									}
								} else {

									agent.LLDPNeighborMap[iface][fabricAtt.SystemName] = append(agent.LLDPNeighborMap[iface][fabricAtt.SystemName], fabricAtt)
									agent.hostAgent.log.Infof("LLDP Adjacency discovered for %s: %s", ifaceStr, fabricAtt.StaticPath)
									needNotify = true
								}
							} else {
								agent.LLDPNeighborMap[iface] = make(map[string][]FabricAttachmentData)
								agent.LLDPNeighborMap[iface][fabricAtt.SystemName] = append(agent.LLDPNeighborMap[iface][fabricAtt.SystemName], fabricAtt)
								agent.hostAgent.log.Infof("LLDP Adjacency discovered for %s: %s", ifaceStr, fabricAtt.StaticPath)
								needNotify = true
							}
							agent.indexMutex.Unlock()
						}
						if needNotify {
							adj := []*FabricAttachmentData{}
							agent.indexMutex.Lock()
							if bridge == "default" {
								for sys := range agent.LLDPNeighborMap[iface] {
									for link := range agent.LLDPNeighborMap[iface][sys] {
										adj = append(adj, &agent.LLDPNeighborMap[iface][sys][link])
									}
								}
							}
							agent.indexMutex.Unlock()
							if bridge != "default" {
								agent.notifyBridge(bridge)
							} else if bond != "" {
								agent.notifyBond(bond)
							} else {
								agent.hostAgent.NotifyFabricAdjacency(iface, adj)
							}
						}
					}
					if bridgeNotify {
						agent.notifyBridge(bridge)
					}
					if bondNotify {
						agent.notifyBond(bond)
					}
				}
				deletedIfaces := []string{}
				agent.indexMutex.Lock()
				for iface := range agent.LLDPIntfMap {
					if _, ok := visited[iface]; !ok {
						delete(agent.LLDPIntfMap, iface)
						// if port is part of a bridge/bond, then bridge/bond output will indicate missing port.
						// skip notifying adjacency loss in this case
						if _, ok := agent.port2BridgeMap[iface]; !ok {
							if _, ok := agent.port2BondMap[iface]; !ok {
								deletedIfaces = append(deletedIfaces, iface)
							}
						}
					}
				}
				agent.indexMutex.Unlock()
				adj := []*FabricAttachmentData{}
				for _, iface := range deletedIfaces {
					agent.hostAgent.NotifyFabricAdjacency(iface, adj)
				}
			}
		}
	}()
}

func (agent *FabricDiscoveryAgentLLDPNMState) GetNeighborData(iface string) ([]*FabricAttachmentData, error) {
	fabAttData := []*FabricAttachmentData{}
	agent.indexMutex.Lock()
	defer agent.indexMutex.Unlock()
	if _, ok := agent.bridge2PortsMap[iface]; ok {
		for port := range agent.bridge2PortsMap[iface] {
			if _, ok := agent.bond2PortsMap[port]; ok {
				fabAttData = agent.getBondAdjacencyLocked(port, fabAttData)
				continue
			}
			for sys := range agent.LLDPNeighborMap[port] {
				for link := range agent.LLDPNeighborMap[port][sys] {
					fabAttData = append(fabAttData, &agent.LLDPNeighborMap[port][sys][link])
				}
			}
		}
		if len(fabAttData) == 0 {
			return nil, fmt.Errorf("LLDP Neighbor Data from NMState is not available yet for %s", iface)
		}
		return fabAttData, nil
	}
	if _, ok := agent.bond2PortsMap[iface]; ok {
		for port := range agent.bond2PortsMap[iface] {
			for sys := range agent.LLDPNeighborMap[port] {
				for link := range agent.LLDPNeighborMap[port][sys] {
					fabAttData = append(fabAttData, &agent.LLDPNeighborMap[port][sys][link])
				}
			}
		}
		if len(fabAttData) == 0 {
			return nil, fmt.Errorf("LLDP Neighbor Data from NMState is not available yet for %s", iface)
		}
		return fabAttData, nil
	}
	fabAttMap, ok := agent.LLDPNeighborMap[iface]
	if !ok {
		return nil, fmt.Errorf("LLDP Neighbor Data from NMState is not available yet for %s", iface)
	}
	for sysName := range fabAttMap {
		for link := range fabAttMap[sysName] {
			fabAttData = append(fabAttData, &agent.LLDPNeighborMap[iface][sysName][link])
		}
	}
	return fabAttData, nil
}

func NewFabricDiscoveryAgentLLDPNMState() FabricDiscoveryAgent {
	return &FabricDiscoveryAgentLLDPNMState{}
}

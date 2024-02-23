//go:build ovscni
// +build ovscni

package hostagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type LLDPInterfaceStateRawSocket struct {
	State        LLDPInterfaceState
	PacketSource *gopacket.PacketSource
}

type FabricDiscoveryAgentLLDPRawSocket struct {
	hostAgent       *HostAgent
	indexMutex      sync.Mutex
	collectTrigger  chan bool
	LLDPIntfMap     map[string]*LLDPInterfaceStateRawSocket
	LLDPNeighborMap map[string]map[string][]FabricAttachmentData
	port2BridgeMap  map[string]string
	bridge2PortsMap map[string]map[string]bool
	port2BondMap    map[string]string
	bond2PortsMap   map[string]map[string]bool
}

func (agent *FabricDiscoveryAgentLLDPRawSocket) RunCommand(cmd string, cmdArgs ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, cmd, cmdArgs...)
	return command.Output()
}

func (agent *FabricDiscoveryAgentLLDPRawSocket) Init(ha *HostAgent) error {
	agent.hostAgent = ha
	agent.collectTrigger = make(chan bool)
	agent.LLDPIntfMap = make(map[string]*LLDPInterfaceStateRawSocket)
	agent.LLDPNeighborMap = make(map[string]map[string][]FabricAttachmentData)
	agent.port2BridgeMap = make(map[string]string)
	agent.bridge2PortsMap = make(map[string]map[string]bool)
	agent.port2BondMap = make(map[string]string)
	agent.bond2PortsMap = make(map[string]map[string]bool)
	if ha.integ_test != nil {
		return nil
	}
	_, err := agent.RunCommand("nmstatectl", "show")
	return err
}

func (agent *FabricDiscoveryAgentLLDPRawSocket) PopulateAdjacencies(adjs map[string][]FabricAttachmentData) {
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

func (agent *FabricDiscoveryAgentLLDPRawSocket) TriggerCollectionDiscoveryData() {
	agent.collectTrigger <- true
}

func (agent *FabricDiscoveryAgentLLDPRawSocket) getBondAdjacencyLocked(bond string, adj []*FabricAttachmentData) []*FabricAttachmentData {
	for port := range agent.bond2PortsMap[bond] {
		for sys := range agent.LLDPNeighborMap[port] {
			for link := range agent.LLDPNeighborMap[port][sys] {
				adj = append(adj, &agent.LLDPNeighborMap[port][sys][link])
			}
		}
	}
	return adj
}

func (agent *FabricDiscoveryAgentLLDPRawSocket) notifyBridge(bridge string) {
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
	agent.hostAgent.log.Infof("lldprawsocket: Collecting for bridge: %s", bridge)
	agent.hostAgent.NotifyFabricAdjacency(bridge, adj)
}

func (agent *FabricDiscoveryAgentLLDPRawSocket) notifyBond(bond string) {
	adj := []*FabricAttachmentData{}
	agent.indexMutex.Lock()
	if bridge, ok := agent.port2BridgeMap[bond]; ok {
		agent.indexMutex.Unlock()
		agent.notifyBridge(bridge)
		return
	}
	adj = agent.getBondAdjacencyLocked(bond, adj)
	agent.indexMutex.Unlock()
	agent.hostAgent.log.Infof("lldprawsocket: Collecting for bond: %s", bond)
	agent.hostAgent.NotifyFabricAdjacency(bond, adj)
}

func (agent *FabricDiscoveryAgentLLDPRawSocket) NewIfRawSocket(iface string) (*gopacket.PacketSource, error) {
	filter := []bpf.RawInstruction{
		{0x28, 0, 0, 0x0000000c},
		{0x15, 0, 1, 0x000088cc},
		{0x6, 0, 0, 0x00040000},
		{0x6, 0, 0, 0x00000000},
	}
	optInt := afpacket.OptInterface(iface)
	optPollTimeout := afpacket.OptPollTimeout(time.Millisecond)
	tPkt, err := afpacket.NewTPacket(optInt, afpacket.SocketRaw, optPollTimeout)
	if err != nil {
		return nil, err
	}
	if err = tPkt.SetBPF(filter); err != nil {
		tPkt.Close()
		return nil, err
	}
	return gopacket.NewPacketSource(tPkt, layers.LayerTypeEthernet), nil
}

func (agent *FabricDiscoveryAgentLLDPRawSocket) CollectDiscoveryData(stopCh <-chan struct{}) {
	if agent.hostAgent.integ_test != nil {
		return
	}
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		agent.hostAgent.log.Debugf("Starting FabricDiscoveryAgentLLDPRawSocket")
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
					agent.hostAgent.log.Errorf("lldprawsocket: nmstatectl failed:%v", err)
					continue
				}
				var base interface{}
				if err := json.Unmarshal(out, &base); err != nil {
					agent.hostAgent.log.Errorf("lldprawsocket: unmarshaling  %v", err)
					continue
				}
				visited := map[string]bool{}
				nmOut := base.(map[string]interface{})
				nmOutInterfaces := nmOut["interfaces"].([]interface{})
				for _, intf := range nmOutInterfaces {
					intfData := intf.(map[string]interface{})
					iface := intfData["name"].(string)
					visited[iface] = true
					// Only look at port/bond-member controlled by an external bridge like ovs
					ctrlrStr, cok := intfData["controller"]
					if !cok && (intfData["type"].(string) != "ovs-bridge") {
						continue
					}
					if cok {
						ctrlr := ctrlrStr.(string)
						if ctrlr != "ovs-system" {
							agent.indexMutex.Lock()
							// Ensure bridge/bond is read before reading the port
							if _, ok := agent.bridge2PortsMap[ctrlr]; !ok {
								if _, ok := agent.bond2PortsMap[ctrlr]; !ok {
									agent.indexMutex.Unlock()
									continue
								}
							}
							if bridge, ok := agent.port2BridgeMap[iface]; ok {
								if ifaceData, ok := agent.LLDPIntfMap[bridge]; !ok {
									agent.indexMutex.Unlock()
									continue
								} else if !ifaceData.State.IsOvsInterface {
									agent.indexMutex.Unlock()
									continue
								}
							} else if bond, ok := agent.port2BondMap[iface]; !ok {
								agent.indexMutex.Unlock()
								continue
							} else if ifaceData, ok := agent.LLDPIntfMap[bond]; !ok {
								agent.indexMutex.Unlock()
								continue
							} else {
								if !ifaceData.State.IsOvsInterface {
									agent.indexMutex.Unlock()
									continue
								}
							}
							agent.indexMutex.Unlock()
						}
					}
					var ok bool
					var ifaceData *LLDPInterfaceStateRawSocket
					agent.indexMutex.Lock()
					if ifaceData, ok = agent.LLDPIntfMap[iface]; !ok {
						var err error
						ifaceData = &LLDPInterfaceStateRawSocket{
							State: LLDPInterfaceState{Enabled: true,
								InterfaceType:  intfData["type"].(string),
								AdminState:     intfData["state"].(string),
								IsOvsInterface: true,
							},
						}
						ifaceMacIsLocal := false
						if intfData["mac-address"] != nil {
							ifaceMacStr := intfData["mac-address"].(string)
							macAddr, err := net.ParseMAC(ifaceMacStr)
							if err == nil {
								ifaceMacIsLocal = (macAddr[0] & 0x02) > 0
							}
						}
						if ifaceData.State.InterfaceType == "ethernet" && !ifaceMacIsLocal {
							agent.hostAgent.log.Infof("lldprawsocket: Capturing LLDP for %v", iface)
							ifaceData.PacketSource, err = agent.NewIfRawSocket(iface)
						}
						if err == nil {
							agent.LLDPIntfMap[iface] = ifaceData
						}
					}
					bridgeNotify := false
					bondNotify := false
					isCompositeIf := false
					var bridge, ifaceStr, bond string
					if ifaceData.State.InterfaceType == "ovs-bridge" {
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
					} else if ifaceData.State.InterfaceType == "bond" {
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
							ifaceStr = "bridge " + bridge + " iface " + iface
						} else {
							ifaceStr = "iface " + iface
						}
						if bond, ok = agent.port2BondMap[iface]; !ok {
							bond = ""
						}
					}
					agent.indexMutex.Unlock()
					if !isCompositeIf {
						var fabricAtt FabricAttachmentData
						needNotify := false
						if ifaceData.PacketSource == nil {
							continue
						}
						pktCnt := 0
						validNbr := false
						for {
							fabricAtt = FabricAttachmentData{}
							if pktCnt >= 10 {
								break
							}
							packet, err := ifaceData.PacketSource.NextPacket()
							pktCnt++
							if err == io.EOF {
								agent.indexMutex.Lock()
								delete(agent.LLDPIntfMap, iface)
								agent.indexMutex.Unlock()
								break
							} else if err != nil {
								continue
							}
							if err := packet.ErrorLayer(); err != nil {
								continue
							}
							if layer := packet.Layer(layers.LayerTypeLinkLayerDiscovery); layer != nil {
								lldpLayer := layer.(*layers.LinkLayerDiscovery)
								PortID := bytes.NewBuffer(lldpLayer.PortID.ID).String()
								l2 := packet.Layer(layers.LayerTypeLinkLayerDiscoveryInfo).(*layers.LinkLayerDiscoveryInfo)
								if l2 != nil {
									remoteIntf := "/pathep-[" + strings.ToLower(PortID) + "]"
									fabricAtt.StaticPath += remoteIntf
									fabricAtt.StaticPath = l2.SysDescription + fabricAtt.StaticPath
									fabricAtt.SystemName = l2.SysName
									if !strings.Contains(fabricAtt.StaticPath, "topology") || !strings.Contains(fabricAtt.StaticPath, "pod") || !strings.Contains(fabricAtt.StaticPath, "node") {
										agent.hostAgent.log.Debugf("lldprawsocket: Skipping invalid staticpath from non-ACI neighbor %s:%s", fabricAtt.SystemName, fabricAtt.StaticPath)
										continue
									}
									validNbr = true

									break
								}
							}
						}
						if !validNbr {
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
									agent.hostAgent.log.Infof("lldprawsocket: LLDP Adjacency updated for %s: %s", ifaceStr, fabricAtt.StaticPath)
									needNotify = true
								}
							} else {

								agent.LLDPNeighborMap[iface][fabricAtt.SystemName] = append(agent.LLDPNeighborMap[iface][fabricAtt.SystemName], fabricAtt)
								agent.hostAgent.log.Infof("lldprawsocket: LLDP Adjacency discovered for %s: %s", ifaceStr, fabricAtt.StaticPath)
								needNotify = true
							}
						} else {
							agent.LLDPNeighborMap[iface] = make(map[string][]FabricAttachmentData)
							agent.LLDPNeighborMap[iface][fabricAtt.SystemName] = append(agent.LLDPNeighborMap[iface][fabricAtt.SystemName], fabricAtt)
							agent.hostAgent.log.Infof("lldprawsocket: LLDP Adjacency discovered for %s: %s", ifaceStr, fabricAtt.StaticPath)
							needNotify = true
						}
						agent.indexMutex.Unlock()
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

func (agent *FabricDiscoveryAgentLLDPRawSocket) GetNeighborData(iface string) ([]*FabricAttachmentData, error) {
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
			return nil, fmt.Errorf("LLDP Neighbor Data from raw socket is not available yet for %s", iface)
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
			return nil, fmt.Errorf("LLDP Neighbor Data from raw socket is not available yet for %s", iface)
		}
		return fabAttData, nil
	}
	fabAttMap, ok := agent.LLDPNeighborMap[iface]
	if !ok {
		return nil, fmt.Errorf("LLDP Neighbor Data from raw socket is not available yet for %s", iface)
	}
	for sysName := range fabAttMap {
		for link := range fabAttMap[sysName] {
			fabAttData = append(fabAttData, &agent.LLDPNeighborMap[iface][sysName][link])
		}
	}
	return fabAttData, nil
}

func NewFabricDiscoveryAgentLLDPRawSocket() FabricDiscoveryAgent {
	return &FabricDiscoveryAgentLLDPRawSocket{}
}

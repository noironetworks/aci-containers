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
					agent.indexMutex.Lock()
					agent.LLDPIntfMap[iface] = &LLDPInterfaceState{
						Enabled:       lldpEnabled,
						InterfaceType: intfData["type"].(string),
						AdminState:    intfData["state"].(string),
					}
					agent.indexMutex.Unlock()
					if lldpEnabled {
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
										agent.hostAgent.log.Infof("LLDP Adjacency updated for iface %s: %s", iface, fabricAtt.StaticPath)
										needNotify = true
									}
								} else {

									agent.LLDPNeighborMap[iface][fabricAtt.SystemName] = append(agent.LLDPNeighborMap[iface][fabricAtt.SystemName], fabricAtt)
									agent.hostAgent.log.Infof("LLDP Adjacency discovered for iface %s: %s", iface, fabricAtt.StaticPath)
									needNotify = true
								}
							} else {
								agent.LLDPNeighborMap[iface] = make(map[string][]FabricAttachmentData)
								agent.LLDPNeighborMap[iface][fabricAtt.SystemName] = append(agent.LLDPNeighborMap[iface][fabricAtt.SystemName], fabricAtt)
								agent.hostAgent.log.Infof("LLDP Adjacency discovered for iface %s: %s", iface, fabricAtt.StaticPath)
								needNotify = true
							}
							agent.indexMutex.Unlock()
						}
						if needNotify {
							adj := []*FabricAttachmentData{}
							agent.indexMutex.Lock()
							for sys := range agent.LLDPNeighborMap[iface] {
								for link := range agent.LLDPNeighborMap[iface][sys] {
									adj = append(adj, &agent.LLDPNeighborMap[iface][sys][link])
								}
							}
							agent.indexMutex.Unlock()
							agent.hostAgent.NotifyFabricAdjacency(iface, adj)
						}
					}
				}
			}
		}
	}()
}

func (agent *FabricDiscoveryAgentLLDPNMState) GetNeighborData(iface string) ([]*FabricAttachmentData, error) {
	fabAttData := []*FabricAttachmentData{}
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

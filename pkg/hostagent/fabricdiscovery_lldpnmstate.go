package hostagent

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type LLDPInterfaceState struct {
	Enabled       bool
	InterfaceType string
	AdminState    string
}

type FabricDiscoveryAgentLLDPNMState struct {
	hostAgent       *HostAgent
	LLDPIntfMap     map[string]*LLDPInterfaceState
	LLDPNeighborMap map[string]map[string]*FabricAttachmentData
}

func (agent *FabricDiscoveryAgentLLDPNMState) RunCommand(cmd string, cmdArgs ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, cmd, cmdArgs...)
	return command.Output()
}

func (agent *FabricDiscoveryAgentLLDPNMState) Init(ha *HostAgent) error {
	agent.hostAgent = ha
	agent.LLDPIntfMap = make(map[string]*LLDPInterfaceState)
	agent.LLDPNeighborMap = make(map[string]map[string]*FabricAttachmentData)
	_, err := agent.RunCommand("nmstatectl", "show")
	return err
}

/* We would need a list of allowed interfaces to enable LLDP On.
   So require specific interfaces to already have enabled LLDP
func (agent *FabricDiscoveryAgentLLDPNMState) enableDiscovery(iface string) error {
	adminState, ok := agent.LLDPIntfMap[iface]
	if !ok {
		return fmt.Errorf("Interface %s not recognized", iface)
	}
	if adminState.Enabled || adminState.InterfaceType != "ethernet" {
		return nil
	}
	enable_lldp_tmpl :=
		"interfaces:\n- name: %s\n  type: ethernet\n  lldp:\n    enabled: true\n"
	enableStr := fmt.Sprintf(enable_lldp_tmpl, iface)
	_, err := agent.RunCommand("nmstatectl", "apply", "-", "<<", "EOL\n", enableStr, "EOL\n")
	if err == nil {
		agent.LLDPIntfMap[iface].Enabled = true
	}
	return err
}
*/
func (agent *FabricDiscoveryAgentLLDPNMState) CollectDiscoveryData(stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		agent.hostAgent.log.Debugf("Starting FabricDiscoveryAgentLLDPNMState")
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				//Scan for new interfaces
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
					agent.LLDPIntfMap[iface] = &LLDPInterfaceState{
						Enabled:       lldpEnabled,
						InterfaceType: intfData["type"].(string),
						AdminState:    intfData["state"].(string),
					}
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
							existingNeighbors, ok := agent.LLDPNeighborMap[iface]
							if ok {
								if existingNeighbor, ok := existingNeighbors[fabricAtt.SystemName]; ok {
									if existingNeighbor.StaticPath != fabricAtt.StaticPath {
										agent.LLDPNeighborMap[iface][fabricAtt.SystemName] = &fabricAtt
										agent.hostAgent.log.Infof("LLDP Adjacency updated for iface %s: %s", iface, fabricAtt.StaticPath)
										needNotify = true
									}
								} else {
									agent.LLDPNeighborMap[iface][fabricAtt.SystemName] = &fabricAtt
									agent.hostAgent.log.Infof("LLDP Adjacency discovered for iface %s: %s", iface, fabricAtt.StaticPath)
									needNotify = true
								}

							} else {
								agent.LLDPNeighborMap[iface] = make(map[string]*FabricAttachmentData)
								agent.LLDPNeighborMap[iface][fabricAtt.SystemName] = &fabricAtt
								agent.hostAgent.log.Infof("LLDP Adjacency discovered for iface %s: %s", iface, fabricAtt.StaticPath)
								needNotify = true
							}

						}
						if needNotify {
							adj := []*FabricAttachmentData{}
							for sys := range agent.LLDPNeighborMap[iface] {
								adj = append(adj, agent.LLDPNeighborMap[iface][sys])
							}
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
		fabAttData = append(fabAttData, fabAttMap[sysName])
	}
	return fabAttData, nil
}

func NewFabricDiscoveryAgentLLDPNMState() FabricDiscoveryAgent {
	return &FabricDiscoveryAgentLLDPNMState{}
}

//go:build ovscni
// +build ovscni

package hostagent

import "fmt"

type FabricDiscoveryAgentLLDPNMState struct{}

func NewFabricDiscoveryAgentLLDPNMState() FabricDiscoveryAgent {
	return &FabricDiscoveryAgentLLDPNMState{}
}
func (agent *FabricDiscoveryAgentLLDPNMState) Init(ha *HostAgent) error {
	return nil
}
func (agent *FabricDiscoveryAgentLLDPNMState) CollectDiscoveryData(stopChain <-chan struct{}) {
}
func (agent *FabricDiscoveryAgentLLDPNMState) TriggerCollectionDiscoveryData() {
}
func (agent *FabricDiscoveryAgentLLDPNMState) GetNeighborData(iface string) ([]*FabricAttachmentData, error) {
	return nil, fmt.Errorf("LLDP Neighbor Data is not available yet for %s", iface)
}
func (agent *FabricDiscoveryAgentLLDPNMState) PopulateAdjacencies(adjs map[string][]FabricAttachmentData) {
}

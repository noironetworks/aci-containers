//go:build !ovscni
// +build !ovscni

package hostagent

import "fmt"

// _lldprawsocket

type FabricDiscoveryAgentLLDPRawSocket struct{}

func NewFabricDiscoveryAgentLLDPRawSocket() FabricDiscoveryAgent {
	return &FabricDiscoveryAgentLLDPRawSocket{}
}
func (agent *FabricDiscoveryAgentLLDPRawSocket) Init(ha *HostAgent) error {
	return nil
}
func (agent *FabricDiscoveryAgentLLDPRawSocket) CollectDiscoveryData(stopChain <-chan struct{}) {
}
func (agent *FabricDiscoveryAgentLLDPRawSocket) TriggerCollectionDiscoveryData() {
}
func (agent *FabricDiscoveryAgentLLDPRawSocket) GetNeighborData(iface string) ([]*FabricAttachmentData, error) {
	return nil, fmt.Errorf("LLDP Neighbor Data is not available yet for %s", iface)
}
func (agent *FabricDiscoveryAgentLLDPRawSocket) PopulateAdjacencies(adjs map[string][]FabricAttachmentData) {
}

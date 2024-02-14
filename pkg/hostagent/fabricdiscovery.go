package hostagent

import "fmt"

const (
	FabricDiscoveryMethodLLDPNMState = iota
	FabricDiscoveryMethodLLDPRawSocket
	FabricDiscoveryMethodStatic
)

type FabricAttachmentData struct {
	StaticPath string `json:"staticPath"`
	SystemName string `json:"systemName"`
}

type FabricDiscoveryAgent interface {
	Init(agent *HostAgent) error
	CollectDiscoveryData(stopCh <-chan struct{})
	TriggerCollectionDiscoveryData()
	GetNeighborData(iface string) ([]*FabricAttachmentData, error)
	PopulateAdjacencies(adjs map[string][]FabricAttachmentData)
}

func (ha *HostAgent) getFabricDiscoveryAgent(method int) FabricDiscoveryAgent {
	switch method {
	case FabricDiscoveryMethodLLDPNMState:
		return NewFabricDiscoveryAgentLLDPNMState()
	case FabricDiscoveryMethodLLDPRawSocket:
		return NewFabricDiscoveryAgentLLDPRawSocket()
	}
	return nil
}

// TBD: Consider passing a profile to make sure only the required methods are run
func (ha *HostAgent) FabricDiscoveryRegistryInit() (err error) {
	ha.fabricDiscoveryRegistry = make(map[int]FabricDiscoveryAgent)
	for method := FabricDiscoveryMethodLLDPNMState; method < FabricDiscoveryMethodStatic; method++ {
		if fabricDiscoveryAgent := ha.getFabricDiscoveryAgent(method); fabricDiscoveryAgent != nil {
			ha.fabricDiscoveryRegistry[method] = ha.getFabricDiscoveryAgent(method)
			err = ha.fabricDiscoveryRegistry[method].Init(ha)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (ha *HostAgent) FabricDiscoveryCollectDiscoveryData(stopCh <-chan struct{}) {
	for method := FabricDiscoveryMethodLLDPNMState; method < FabricDiscoveryMethodStatic; method++ {
		ha.fabricDiscoveryRegistry[method].CollectDiscoveryData(stopCh)
	}
}

func (ha *HostAgent) FabricDiscoveryTriggerCollectionDiscoveryData() {
	for method := FabricDiscoveryMethodLLDPNMState; method < FabricDiscoveryMethodStatic; method++ {
		ha.fabricDiscoveryRegistry[method].TriggerCollectionDiscoveryData()
	}
}

func (ha *HostAgent) FabricDiscoveryPopulateAdjacencies(method int, adjs map[string][]FabricAttachmentData) {
	ha.fabricDiscoveryRegistry[method].PopulateAdjacencies(adjs)
}

func (ha *HostAgent) GetFabricDiscoveryNeighborDataLocked(iface string) ([]*FabricAttachmentData, error) {
	err := fmt.Errorf("Interface %s not discovered or does not have a neighbor", iface)
	for method := FabricDiscoveryMethodLLDPNMState; method < FabricDiscoveryMethodStatic; method++ {
		if adjs, err := ha.fabricDiscoveryRegistry[method].GetNeighborData(iface); err == nil {
			return adjs, err
		}
	}
	return nil, err
}

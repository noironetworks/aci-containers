package hostagent

type FabricDiscoveryMethod string

const (
	FabricDiscoveryLLDPNMState FabricDiscoveryMethod = "LLDP-nmstate"
	FabricDiscoveryStatic      FabricDiscoveryMethod = "Static"
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
}

func GetFabricDiscoveryAgent(method FabricDiscoveryMethod) FabricDiscoveryAgent {

	switch method {
	case FabricDiscoveryLLDPNMState:
		return NewFabricDiscoveryAgentLLDPNMState()
	}
	return nil
}

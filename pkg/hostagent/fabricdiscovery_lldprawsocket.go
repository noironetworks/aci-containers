//go:build ovscni
// +build ovscni

package hostagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/cenkalti/backoff/v4"
	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	libovsdbclient "github.com/ovn-org/libovsdb/client"
	libovsdbmodel "github.com/ovn-org/libovsdb/model"
	"golang.org/x/net/bpf"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type LLDPOp int

const (
	LLDPOpIfAdd LLDPOp = 0
	LLDPOpIfDel LLDPOp = 1
	LLDPOpIfMod LLDPOp = 2
)

const (
	_                  = iota
	LLDPIfTypeBond int = 1 + iota
	LLDPIfTypeBondSlave
	LLDPIfTypeBridge
	LLDPIfTypeBridgeSlave
	LLDPIfTypeUnclassified
)

type LLDPInventory struct {
	LLDPIntfMap     map[string]*LLDPInterfaceStateRawSocket
	LLDPNeighborMap map[string]map[string][]FabricAttachmentData
	intfTrigger     chan *LLDPInterfaceMessage
	intfMutex       sync.Mutex
}

type LLDPInterfaceMessage struct {
	Name   string
	State  LLDPInterfaceState
	Bridge string
	Bond   string
	Op     LLDPOp
}

type LLDPNotifyMessage struct {
	Name       string
	fabAttData []FabricAttachmentData
}

type LLDPInterfaceStateRawSocket struct {
	State        LLDPInterfaceState
	Bridge       string
	Bond         string
	PacketSource *gopacket.PacketSource
}

type FabricDiscoveryAgentLLDPRawSocket struct {
	hostAgent          *HostAgent
	dbModelReq         *libovsdbmodel.DBModel
	ovsdbClient        libovsdbclient.Client
	indexMutex         sync.Mutex
	collectTrigger     chan bool
	LLDPIntfMap        map[string]*LLDPInterfaceStateRawSocket
	LLDPNeighborMap    map[string]map[string][]FabricAttachmentData
	LLDPDB             LLDPInventory
	LLDPNotifications  chan *LLDPNotifyMessage
	port2BridgeMap     map[string]string
	port2OvsBridgeMap  map[string]string
	bridge2PortsMap    map[string]map[string]bool
	ovsBridge2PortsMap map[string]map[string]bool
	port2BondMap       map[string]string
	bond2PortsMap      map[string]map[string]bool
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
	agent.port2OvsBridgeMap = make(map[string]string)
	agent.bridge2PortsMap = make(map[string]map[string]bool)
	agent.ovsBridge2PortsMap = make(map[string]map[string]bool)
	agent.port2BondMap = make(map[string]string)
	agent.bond2PortsMap = make(map[string]map[string]bool)
	agent.LLDPDB = LLDPInventory{
		LLDPIntfMap:     make(map[string]*LLDPInterfaceStateRawSocket),
		LLDPNeighborMap: make(map[string]map[string][]FabricAttachmentData),
		intfTrigger:     make(chan *LLDPInterfaceMessage, 200),
	}
	agent.LLDPNotifications = make(chan *LLDPNotifyMessage, 200)
	if ha.integ_test != nil {
		return nil
	}
	agent.hostAgent.log.Info("FabricDiscoveryAgentLLDPRawSocket: Init")
	_, err := agent.RunCommand("ip", "-j", "link", "show")
	if err != nil {
		return err
	}
	if ha.config.ChainedModeOvsDBSocket != "" {
		agent.dbModelReq, err = libovsdbmodel.NewDBModel("Open_vSwitch", map[string]libovsdbmodel.Model{"Bridge": &MyBridge{}, "Port": &MyPort{}})
		if err != nil {
			agent.hostAgent.log.Errorf("Failed to create OVS client DBModel:%s", err)
			return nil
		}
		agent.ovsdbClient, err = libovsdbclient.NewOVSDBClient(agent.dbModelReq,
			libovsdbclient.WithEndpoint("unix:"+agent.hostAgent.config.ChainedModeOvsDBSocket),
			libovsdbclient.WithReconnect(time.Minute, &backoff.ConstantBackOff{Interval: 5 * time.Second}))
		if err != nil {
			agent.hostAgent.log.Errorf("Failed to create OVSDB client:%s", err)
			return nil
		}
		agent.hostAgent.log.Infof("Attempting OVSDB client connection")
		err = agent.ovsdbClient.Connect(context.Background())
		if err != nil {
			time.Sleep(time.Minute)
			if agent.ovsdbClient.Connected() {
				return nil
			}
			agent.hostAgent.log.Errorf("OVSDB client connection failed:%s", err)
			return nil
		}
	}
	agent.hostAgent.log.Info("FabricDiscoveryAgentLLDPRawSocket Init Complete")
	return nil
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

func (agent *FabricDiscoveryAgentLLDPRawSocket) notifyInternal() {

}

func (agent *FabricDiscoveryAgentLLDPRawSocket) notifyBridge(bridge string) {
	adj := []*FabricAttachmentData{}
	agent.indexMutex.Lock()
	if _, ok := agent.ovsBridge2PortsMap[bridge]; ok {
		for port := range agent.ovsBridge2PortsMap[bridge] {
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

	} else {
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
	if bridge, ok := agent.port2OvsBridgeMap[bond]; ok {
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

func (agent *FabricDiscoveryAgentLLDPRawSocket) CollectIntfData(base interface{}, targetType string, visited map[string]bool) {
	ipLinkOut := base.([]interface{})
	currPortMap := make(map[string]map[string]bool)
	currBondMap := make(map[string]map[string]bool)
	notifyBridge := map[string]bool{}
	notifyBond := map[string]bool{}
	agent.indexMutex.Lock()
	for _, intf := range ipLinkOut {
		intfData := intf.(map[string]interface{})
		var bridge string
		ifaceName := intfData["ifname"]
		if ifaceName == nil {
			continue
		}
		iface := ifaceName.(string)
		if _, ok := visited[iface]; ok {
			continue
		}
		visited[iface] = true
		// skip unsupported ifs
		linkType := intfData["link_type"].(string)
		if linkType != "ether" {
			continue
		}
		var ok bool
		var ifaceData *LLDPInterfaceStateRawSocket
		var bondIface, bridgeIface string
		ifaceType := intfData["link_type"].(string)
		if linkFlagData, ok := intfData["flags"]; ok {
			linkFlags := linkFlagData.([]interface{})
			for _, linkFlag := range linkFlags {
				switch linkFlag.(string) {
				case "MASTER":
					{
						ifaceType = "bond"
					}
				case "SLAVE":
					{
						ifaceType = "bond_slave"
					}
				}
			}
		}
		ifaceData = &LLDPInterfaceStateRawSocket{
			State: LLDPInterfaceState{Enabled: true,
				InterfaceType: ifaceType,
				AdminState:    intfData["operstate"].(string),
			},
		}
		if linkMaster, ok := intfData["master"]; ok {
			if linkMaster.(string) == "ovs-system" {
				ifaceData.State.IsOvsInterface = true
			} else if targetType == "bond_slave" {
				bondIface = linkMaster.(string)
			} else if targetType == "bond" {
				bridgeIface = linkMaster.(string)
			} else if targetType == "bridge_slave" {
				bridgeIface = linkMaster.(string)
			}
		}
		ifaceMacIsLocal := false
		if intfData["address"] != nil {
			ifaceMacStr := intfData["address"].(string)
			macAddr, err := net.ParseMAC(ifaceMacStr)
			if err == nil {
				ifaceMacIsLocal = (macAddr[0] & 0x02) > 0
			}
		}
		if ifaceData.State.IsOvsInterface {
			if bridge, ok = agent.port2OvsBridgeMap[iface]; !ok {
				bridge = "default"
			}
		} else {
			bridge = bridgeIface
			if bridgeIface == "" {
				bridge = "default"
			}
		}
		ifaceData.Bridge = bridge
		ifaceData.Bond = bondIface
		if oldIfaceData, ok := agent.LLDPIntfMap[iface]; !ok {
			if (ifaceData.State.InterfaceType == "individual") ||
				(ifaceData.State.InterfaceType == "bridge_slave") ||
				(ifaceData.State.InterfaceType == "bond_slave") && !ifaceMacIsLocal {
				agent.LLDPDB.intfTrigger <- &LLDPInterfaceMessage{
					Name:   iface,
					State:  ifaceData.State,
					Bridge: ifaceData.Bridge,
					Bond:   ifaceData.Bond,
					Op:     LLDPOpIfAdd,
				}
			}
			agent.LLDPIntfMap[iface] = ifaceData
		} else if (ifaceData.State != oldIfaceData.State) || (ifaceData.Bridge != oldIfaceData.Bridge) ||
			(ifaceData.Bond != oldIfaceData.Bond) {
			agent.LLDPDB.intfTrigger <- &LLDPInterfaceMessage{
				Name:   iface,
				State:  ifaceData.State,
				Bridge: bridgeIface,
				Bond:   bondIface,
				Op:     LLDPOpIfMod,
			}
		}
		switch targetType {
		case "bond_slave":
			{
				if bondIface != "" {
					if _, ok := currPortMap[bondIface]; !ok {
						currPortMap[bondIface] = make(map[string]bool)
					}
					currPortMap[bondIface][iface] = true
					agent.port2BondMap[iface] = bondIface
					if _, ok := agent.bond2PortsMap[bondIface]; !ok {
						agent.bond2PortsMap[bondIface] = make(map[string]bool)
					}
					if _, ok := agent.bond2PortsMap[bondIface][iface]; !ok {
						agent.bond2PortsMap[bondIface][iface] = true
						notifyBond[bondIface] = true
						agent.hostAgent.log.Debugf("Adding %s to bond %s", iface, bondIface)
					}
				}
			}
		case "bond", "bridge_slave":
			{
				if ifaceType == "bond" {
					bondIface = iface
					currBondMap[bondIface] = make(map[string]bool)
					if _, ok := agent.bond2PortsMap[bondIface]; !ok {
						agent.bond2PortsMap[bondIface] = make(map[string]bool)
					}
				}
				if bridgeIface != "" {
					if _, ok := currPortMap[bridgeIface]; !ok {
						currPortMap[bridgeIface] = make(map[string]bool)
					}
					currPortMap[bridgeIface][iface] = true
					agent.port2BridgeMap[iface] = bridgeIface
					if _, ok := agent.bridge2PortsMap[bridgeIface]; !ok {
						agent.bridge2PortsMap[bridgeIface] = make(map[string]bool)
					}
					if _, ok := agent.bridge2PortsMap[bridgeIface][iface]; !ok {
						agent.hostAgent.log.Debugf("Adding %s to bridge %s", iface, bridgeIface)
						agent.bridge2PortsMap[bridgeIface][iface] = true
						notifyBridge[bridgeIface] = true
					}
				}

			}
		case "bridge":
			{
				bridgeIface = iface
				currPortMap[bridgeIface] = make(map[string]bool)
				if _, ok := agent.bridge2PortsMap[bridgeIface]; !ok {
					agent.bridge2PortsMap[bridgeIface] = make(map[string]bool)
				}
			}
		}
	}
	// Handle deletes
	switch targetType {
	case "bond":
		{
			for bond := range agent.bond2PortsMap {
				if _, ok := currBondMap[bond]; !ok {
					if _, ok := visited[bond]; !ok {
						for mbrPort := range agent.bond2PortsMap[bond] {
							delete(agent.port2BondMap, mbrPort)
						}
						delete(agent.bond2PortsMap, bond)
						notifyBond[bond] = true
					}
				}
			}
		}
	case "bond_slave":
		{
			for bond := range agent.bond2PortsMap {
				for currPort := range agent.bond2PortsMap[bond] {
					if _, ok := currPortMap[bond][currPort]; !ok {
						delete(agent.bond2PortsMap[bond], currPort)
						agent.hostAgent.log.Debugf("Deleting %s from bond %s", currPort, bond)
						if currBond, ok := agent.port2BondMap[currPort]; ok {
							if currBond == bond {
								delete(agent.port2BondMap, currPort)
							}
						}
					}
				}
			}
		}
	case "bridge":
		{
			for bridge := range agent.bridge2PortsMap {
				if _, ok := currPortMap[bridge]; !ok {
					if _, ok := visited[bridge]; !ok {
						for mbrPort := range agent.bridge2PortsMap[bridge] {
							delete(agent.port2BridgeMap, mbrPort)
						}
						delete(agent.bridge2PortsMap, bridge)
						notifyBridge[bridge] = true
					}
				}
			}
		}
	case "bridge_slave":
		{
			for bridge := range agent.bridge2PortsMap {
				for currPort := range agent.bridge2PortsMap[bridge] {
					if _, ok := currPortMap[bridge][currPort]; !ok {
						bondSkipped := false
						if _, ok2 := agent.bond2PortsMap[currPort]; ok2 {
							if _, ok3 := visited[currPort]; ok3 {
								bondSkipped = true
							}
						}
						if !bondSkipped {
							delete(agent.bridge2PortsMap[bridge], currPort)
							agent.hostAgent.log.Debugf("Deleting %s from bridge %s", currPort, bridge)
							if currBridge, ok := agent.port2BridgeMap[currPort]; ok {
								if currBridge == bridge {
									delete(agent.port2BridgeMap, currPort)
								}
							}
						}
					}
				}
			}
		}
	}
	agent.indexMutex.Unlock()
	for bond := range notifyBond {
		agent.notifyBond(bond)
	}
	for bridge := range notifyBridge {
		agent.notifyBridge(bridge)
	}
}

type MyBridge struct {
	UUID  string   `ovsdb:"_uuid"`
	Name  string   `ovsdb:"name"`
	Ports []string `ovsdb:"ports"`
}

type MyPort struct {
	UUID string `ovsdb:"_uuid"`
	Name string `ovsdb:"name"`
}

func (agent *FabricDiscoveryAgentLLDPRawSocket) OnAdd(table string, mdl libovsdbmodel.Model) {
	switch table {
	case "Bridge":
		{
			bridge := mdl.(*MyBridge)
			rcI := agent.ovsdbClient.Cache().Table("Port")
			agent.indexMutex.Lock()
			agent.ovsBridge2PortsMap[bridge.Name] = make(map[string]bool)
			for _, port := range bridge.Ports {
				row := rcI.Row(port)
				if iface, ok := row.(*MyPort); ok {
					agent.ovsBridge2PortsMap[bridge.Name][iface.Name] = true
					agent.port2OvsBridgeMap[iface.Name] = bridge.Name
				}
			}
			agent.indexMutex.Unlock()
			agent.notifyBridge(bridge.Name)
		}
	case "Port":
		{
			// Nothing to do here
		}
	}
}

func (agent *FabricDiscoveryAgentLLDPRawSocket) OnUpdate(table string, old libovsdbmodel.Model, mdl libovsdbmodel.Model) {
	switch table {
	case "Bridge":
		{
			bridge := mdl.(*MyBridge)
			visited := make(map[string]bool)
			rcI := agent.ovsdbClient.Cache().Table("Port")
			for _, port := range bridge.Ports {
				row := rcI.Row(port)
				if iface, ok := row.(*MyPort); ok {
					agent.indexMutex.Lock()
					agent.ovsBridge2PortsMap[bridge.Name][iface.Name] = true
					agent.indexMutex.Unlock()
					visited[iface.Name] = true
				}
			}
			agent.indexMutex.Lock()
			for port, _ := range agent.ovsBridge2PortsMap[bridge.Name] {
				if _, ok := visited[port]; !ok {
					delete(agent.ovsBridge2PortsMap[bridge.Name], port)
				}
			}
			agent.indexMutex.Unlock()
			agent.notifyBridge(bridge.Name)
		}
	case "Port":
		{
			// Nothing to do here
		}
	}
}

func (agent *FabricDiscoveryAgentLLDPRawSocket) OnDelete(table string, mdl libovsdbmodel.Model) {
	switch table {
	case "Bridge":
		{
			bridge := mdl.(*MyBridge)
			agent.indexMutex.Lock()
			if _, ok := agent.ovsBridge2PortsMap[bridge.Name]; ok {
				for port := range agent.ovsBridge2PortsMap[bridge.Name] {
					if currBridge, ok := agent.port2OvsBridgeMap[port]; ok {
						if currBridge == bridge.Name {
							delete(agent.port2OvsBridgeMap, port)
						}
					}
				}
				delete(agent.ovsBridge2PortsMap, bridge.Name)
			}
			agent.indexMutex.Unlock()
			agent.notifyBridge(bridge.Name)
		}
	case "Port":
		{
			port := mdl.(*MyPort)
			agent.indexMutex.Lock()
			bridge, ok := agent.port2OvsBridgeMap[port.Name]
			if ok {
				delete(agent.ovsBridge2PortsMap[bridge], port.Name)
			}
			agent.indexMutex.Unlock()
			if bridge != "" {
				agent.notifyBridge(bridge)
			}
		}
	}
}

func (agent *FabricDiscoveryAgentLLDPRawSocket) MonitorOvsDB(stopCh <-chan struct{}) {
	if agent.ovsdbClient == nil {
		return
	}
	go func() {
		agent.ovsdbClient.MonitorAll()
		rcB := agent.ovsdbClient.Cache().Table("Bridge")
		rcI := agent.ovsdbClient.Cache().Table("Port")
		for _, uuid := range rcB.Rows() {
			row := rcB.Row(uuid)
			bridge := row.(*MyBridge)
			agent.indexMutex.Lock()
			agent.ovsBridge2PortsMap[bridge.Name] = make(map[string]bool)
			for _, ifaceUuid := range bridge.Ports {
				row := rcI.Row(ifaceUuid)
				if iface, ok := row.(*MyPort); ok {
					agent.ovsBridge2PortsMap[bridge.Name][iface.Name] = true
					agent.port2OvsBridgeMap[iface.Name] = bridge.Name
				}
			}
			agent.indexMutex.Unlock()
		}
		agent.ovsdbClient.Cache().AddEventHandler(agent)
		agent.ovsdbClient.Cache().Run(stopCh)
		agent.ovsdbClient.Close()
	}()

}

func (agent *FabricDiscoveryAgentLLDPRawSocket) CaptureLLDP(stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {

			select {
			case <-stopCh:
				agent.LLDPDB.intfMutex.Lock()
				for _, ifaceData := range agent.LLDPDB.LLDPIntfMap {
					ifaceData.PacketSource = nil
				}
				agent.LLDPDB.intfMutex.Unlock()
				return
			case lldpIntfRequest := <-agent.LLDPDB.intfTrigger:
				{
					agent.LLDPDB.intfMutex.Lock()
					switch lldpIntfRequest.Op {
					case LLDPOpIfAdd:
						{
							if _, ok := agent.LLDPDB.LLDPIntfMap[lldpIntfRequest.Name]; !ok {
								var err error
								ifaceData := &LLDPInterfaceStateRawSocket{
									State:  lldpIntfRequest.State,
									Bridge: lldpIntfRequest.Bridge,
									Bond:   lldpIntfRequest.Bond,
								}
								ifaceData.PacketSource, err = agent.NewIfRawSocket(lldpIntfRequest.Name)
								if err != nil {
									ifaceData.PacketSource = nil
								} else {

									agent.hostAgent.log.Infof("lldprawsocket: Capturing LLDP for %v", lldpIntfRequest.Name)
								}
								agent.LLDPDB.LLDPIntfMap[lldpIntfRequest.Name] = ifaceData
							}
						}
					case LLDPOpIfDel:
						{
							delete(agent.LLDPDB.LLDPIntfMap, lldpIntfRequest.Name)
							delete(agent.LLDPDB.LLDPNeighborMap, lldpIntfRequest.Name)
						}
					case LLDPOpIfMod:
						if _, ok := agent.LLDPDB.LLDPIntfMap[lldpIntfRequest.Name]; ok {
							ifaceData := &LLDPInterfaceStateRawSocket{
								State:  lldpIntfRequest.State,
								Bridge: lldpIntfRequest.Bridge,
								Bond:   lldpIntfRequest.Bond,
							}
							ifaceData.PacketSource = agent.LLDPDB.LLDPIntfMap[lldpIntfRequest.Name].PacketSource

							agent.LLDPDB.LLDPIntfMap[lldpIntfRequest.Name] = ifaceData
						}
					}
					agent.LLDPDB.intfMutex.Unlock()
				}
			case <-ticker.C:
				{
					agent.LLDPDB.intfMutex.Lock()
					for iface, ifaceData := range agent.LLDPDB.LLDPIntfMap {
						var fabricAtt FabricAttachmentData
						needNotify := false
						if ifaceData.PacketSource == nil {
							var err error
							ifaceData.PacketSource, err = agent.NewIfRawSocket(iface)
							if err != nil {
								ifaceData.PacketSource = nil
								continue
							}
							agent.LLDPDB.LLDPIntfMap[iface].PacketSource = ifaceData.PacketSource
							agent.hostAgent.log.Infof("lldprawsocket: Capturing LLDP for %v", iface)
						}
						pktCnt := 0
						validNbr := false
						var ifaceStr string
						if ifaceData.Bridge != "default" {
							ifaceStr = "bridge " + ifaceData.Bridge + " iface " + iface
						} else {
							ifaceStr = "iface " + iface
						}
						for {
							fabricAtt = FabricAttachmentData{}
							if pktCnt >= 10 {
								break
							}
							packet, err := ifaceData.PacketSource.NextPacket()
							pktCnt++
							if err == io.EOF {
								agent.LLDPDB.LLDPIntfMap[iface].PacketSource = nil
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
						existingNeighbors, ok := agent.LLDPDB.LLDPNeighborMap[iface]
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
									agent.LLDPDB.LLDPNeighborMap[iface][fabricAtt.SystemName] = append(agent.LLDPDB.LLDPNeighborMap[iface][fabricAtt.SystemName], fabricAtt)
									agent.hostAgent.log.Infof("lldprawsocket: LLDP Adjacency updated for %s: %s", ifaceStr, fabricAtt.StaticPath)
									needNotify = true
								}
							} else {

								agent.LLDPDB.LLDPNeighborMap[iface][fabricAtt.SystemName] = append(agent.LLDPDB.LLDPNeighborMap[iface][fabricAtt.SystemName], fabricAtt)
								agent.hostAgent.log.Infof("lldprawsocket: LLDP Adjacency discovered for %s: %s", ifaceStr, fabricAtt.StaticPath)
								needNotify = true
							}
						} else {
							agent.LLDPDB.LLDPNeighborMap[iface] = make(map[string][]FabricAttachmentData)
							agent.LLDPDB.LLDPNeighborMap[iface][fabricAtt.SystemName] = append(agent.LLDPNeighborMap[iface][fabricAtt.SystemName], fabricAtt)
							agent.hostAgent.log.Infof("lldprawsocket: LLDP Adjacency discovered for %s: %s", ifaceStr, fabricAtt.StaticPath)
							needNotify = true
						}
						if needNotify {
							adjs := []FabricAttachmentData{}
							for _, sysAdj := range agent.LLDPDB.LLDPNeighborMap[iface] {
								adjs = append(adjs, sysAdj...)
							}

							lldpNotify := &LLDPNotifyMessage{
								Name:       iface,
								fabAttData: adjs,
							}
							agent.LLDPNotifications <- lldpNotify
						}
					}
					agent.LLDPDB.intfMutex.Unlock()
				}
			}
		}
	}()
}

func (agent *FabricDiscoveryAgentLLDPRawSocket) CollectDiscoveryData(stopCh <-chan struct{}) {
	if agent.hostAgent.integ_test != nil {
		return
	}
	agent.MonitorOvsDB(stopCh)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		agent.hostAgent.log.Debugf("Starting FabricDiscoveryAgentLLDPRawSocket")
		for {
			select {
			case <-stopCh:
				return
			case lldpNotifyRequest := <-agent.LLDPNotifications:
				{
					adjs := []*FabricAttachmentData{}
					var bond, bridge string
					agent.indexMutex.Lock()
					if ifaceData, ok := agent.LLDPIntfMap[lldpNotifyRequest.Name]; ok {
						bridge = ifaceData.Bridge
						bond = ifaceData.Bond
					}
					for _, adj := range lldpNotifyRequest.fabAttData {
						if _, ok := agent.LLDPNeighborMap[lldpNotifyRequest.Name][adj.SystemName]; !ok {

							agent.LLDPNeighborMap[lldpNotifyRequest.Name] = make(map[string][]FabricAttachmentData)
						}
						agent.LLDPNeighborMap[lldpNotifyRequest.Name][adj.SystemName] = append(agent.LLDPNeighborMap[lldpNotifyRequest.Name][adj.SystemName], adj)
						adjs = append(adjs, &adj)
					}
					agent.indexMutex.Unlock()
					if bridge != "default" {
						agent.notifyBridge(bridge)
					} else if bond != "" {
						agent.notifyBond(bond)
					} else {
						agent.hostAgent.NotifyFabricAdjacency(lldpNotifyRequest.Name, adjs)
					}
				}
			case <-agent.collectTrigger:
			case <-ticker.C:
				//Scan for new interfaces
				if agent.hostAgent.integ_test != nil {
					continue
				}
				visited := map[string]bool{}
				cmds := map[string][]string{
					"bond":         {"ip", "-j", "link", "show", "type", "bond"},
					"bond_slave":   {"ip", "-j", "link", "show", "type", "bond_slave"},
					"bridge":       {"ip", "-j", "link", "show", "type", "bridge"},
					"bridge_slave": {"ip", "-j", "link", "show", "type", "bridge_slave"},
					"individual":   {"ip", "-j", "link", "show"}}
				for _, targetType := range []string{"bond", "bond_slave", "bridge", "bridge_slave", "individual"} {
					cmdStr := ""
					for _, arg := range cmds[targetType] {
						cmdStr += arg + " "
					}
					out, err := agent.RunCommand(cmds[targetType][0], cmds[targetType][1:]...)
					if err != nil {
						agent.hostAgent.log.Errorf("lldprawsocket: %s command failed:%v", cmdStr, err)
						continue
					}
					var base interface{}
					if err := json.Unmarshal(out, &base); err != nil {
						agent.hostAgent.log.Errorf("lldprawsocket: unmarshaling failed %v", err)
						continue
					}
					agent.CollectIntfData(base, targetType, visited)
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
					agent.LLDPDB.intfTrigger <- &LLDPInterfaceMessage{
						Name: iface,
						Op:   LLDPOpIfDel,
					}
					agent.hostAgent.NotifyFabricAdjacency(iface, adj)
				}
			}
		}
	}()
	agent.CaptureLLDP(stopCh)
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

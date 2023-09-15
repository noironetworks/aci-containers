package hostagent

import (
	"context"
	netpolicy "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"reflect"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sort"
	"testing"
	"time"
)

func testnetattach(name, namespace, config string, annot map[string]string) *netpolicy.NetworkAttachmentDefinition {
	netattachdef := &netpolicy.NetworkAttachmentDefinition{
		Spec: netpolicy.NetworkAttachmentDefinitionSpec{
			Config: config,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: annot,
		},
	}

	return netattachdef
}

func testFabricVlanPool(namespace, name, vlanStr string) *fabattv1.FabricVlanPool {
	fabricVlanPool := &fabattv1.FabricVlanPool{
		Spec: fabattv1.FabricVlanPoolSpec{
			Vlans: []string{vlanStr},
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}

	return fabricVlanPool
}

func TestNetAttachmentDef(t *testing.T) {
	configJsondata := `
		{ 
			"cniVersion": "0.3.1", 
			"name": "k8s-pod-network",
			"plugins": [ { "type": "opflex-agent-cni","log_level": "debug", "ipam": { "type": "opflex-agent-cni-ipam" }}]
		}`

	resourceAnnot := make(map[string]string)
	resourceAnnot["k8s.v1.cni.cncf.io/resourceName"] = "mellanox.com/cx5_sriov_switchdev"
	agent := testAgent()
	agent.config.OvsHardwareOffload = true
	agent.fakeNetAttachDefSource.Add(testnetattach("default", "kube-system", configJsondata, resourceAnnot))
	agent.run()

	actual := &NetworkAttachmentData{
		Name:        "default",
		Namespace:   "kube-system",
		Config:      configJsondata,
		Annot:       "mellanox.com/cx5_sriov_switchdev",
		KnownAnnots: map[string]string{},
	}

	expected := agent.netattdefmap["default"]
	assert.Equal(t, actual, expected)
}

func TestNetAttachmentDefWithoutAcii(t *testing.T) {
	configJsondata := `
                {
                        "cniVersion": "0.3.1",
                        "name": "k8s-pod-network",
                        "plugins": [ { "type": "other-cni","log_level": "debug", "ipam": { "type": "other-cni-ipam" }}]
                }`

	resourceAnnot := make(map[string]string)
	resourceAnnot["k8s.v1.cni.cncf.io/resourceName"] = "mellanox.com/cx5_sriov_switchdev"
	agent := testAgent()
	agent.config.OvsHardwareOffload = true
	agent.fakeNetAttachDefSource.Add(testnetattach("default", "kube-system", configJsondata, resourceAnnot))
	agent.run()

	var actual *NetworkAttachmentData

	expected := agent.netattdefmap["default"]
	assert.Equal(t, actual, expected)
}

func TestNetAttachmentDefDelete(t *testing.T) {
	configJsondata := `
                {
                        "cniVersion": "0.3.1",
                        "name": "k8s-pod-network",
                        "plugins": [ { "type": "opflex-agent-cni","log_level": "debug", "ipam": { "type": "opflex-agent-cni-ipam" }}]
                }`

	resourceAnnot := make(map[string]string)
	resourceAnnot["k8s.v1.cni.cncf.io/resourceName"] = "mellanox.com/cx5_sriov_switchdev"
	agent := testAgent()
	agent.config.OvsHardwareOffload = true
	agent.fakeNetAttachDefSource.Add(testnetattach("default", "kube-system", configJsondata, resourceAnnot))
	agent.run()

	var actual *NetworkAttachmentData
	delete(agent.netattdefmap, "default")
	expected := agent.netattdefmap["default"]
	assert.Equal(t, actual, expected)
}

func getChainedModeConfig(nodename string) *HostAgentConfig {
	return &HostAgentConfig{
		NodeName:              nodename,
		LogLevel:              "debug",
		AciPrefix:             "ocpbm1",
		AciVrf:                "ocp-bm-1-vrf",
		AciVrfTenant:          "common",
		ChainedMode:           true,
		PrimaryCniPath:        "/mnt/cni-conf/cni/net.d/10-ovn-kubernetes.conf",
		AciUseGlobalScopeVlan: true,
	}

}

func TestNADVlanAnnotValidation(t *testing.T) {
	_, err1 := validateVlanAnnotation("[7-6]")
	assert.NotNil(t, err1, err1)
	expectedStr2 := "[1,2,3,4,6-10]"
	actualStr2, err2 := validateVlanAnnotation(expectedStr2)
	assert.Nil(t, err2, "valid annotation")
	assert.Equal(t, actualStr2, expectedStr2)
	_, err3 := validateVlanAnnotation("[5 4]")
	assert.NotNil(t, err3, err3)
	expectedStr3 := "[1,2,3,4]"
	actualStr3, err4 := validateVlanAnnotation(expectedStr3)
	assert.Nil(t, err4, "valid annotation")
	assert.Equal(t, actualStr3, expectedStr3)
	_, err5 := validateVlanAnnotation("[5")
	assert.NotNil(t, err5, err5)
}

func TestNADSRIOVCRUD(t *testing.T) {
	testenv := &envtest.Environment{CRDDirectoryPaths: []string{"./testdata"}}
	cfg, err := testenv.Start()
	assert.Nil(t, err, "testenv start")
	kubeClient, err := kubernetes.NewForConfig(cfg)
	assert.Nil(t, err, "clientset create")

	configJsondata := `{ "cniVersion":"0.3.1", "name":"sriov-net-1","plugins":[{"name":"sriov-net-1","cniVersion":"0.3.1","type":"sriov","vlan":0,"trust":"on","vlanQoS":0,"capabilities":{"ips":true},"link_state":"auto", "ipam": {"type": "whereabouts","range": "192.168.64.0/24", "exclude": ["192.168.64.0/32", "192.168.64.1/32", "192.168.64.254/32"]}}, {"supportedVersions": [ "0.3.0", "0.3.1", "0.4.0" ], "type": "netop-cni", "chaining-mode": true }]}`

	resourceAnnot := make(map[string]string)
	resourceAnnot["k8s.v1.cni.cncf.io/resourceName"] = "openshift.io/enp216s0f0"
	resourceAnnot[vlanAnnot] = "[100,101,195-200]"
	agent := testAgentEnvtest(getChainedModeConfig(nodename), kubeClient, cfg)
	configmapData := map[string]string{
		nodename: `{"resourceList":[{"resourceName":"enp216s0f0","selectors":{"vendors":["8086"],"devices":["154c"],"pfNames":["enp216s0f0#0-15"],"rootDevices":["0000:d8:00.0"],"IsRdma":false,"NeedVhostNet":false},"SelectorObj":null}]}`,
	}
	kubeClient.CoreV1().Namespaces().Create(context.Background(), mkNamespace("aci-containers-system", "", "", ""), metav1.CreateOptions{})
	kubeClient.CoreV1().ConfigMaps("openshift-sriov-network-operator").Create(context.Background(), mkConfigMap("openshift-sriov-network-operator", "device-plugin-config", configmapData), metav1.CreateOptions{})
	kubeClient.CoreV1().Namespaces().Create(context.Background(), mkNamespace("openshift-sriov-network-operator", "", "", ""), metav1.CreateOptions{})
	kubeClient.CoreV1().ConfigMaps("openshift-sriov-network-operator").Create(context.Background(), mkConfigMap("openshift-sriov-network-operator", "device-plugin-config", configmapData), metav1.CreateOptions{})
	agent.fakeFabricVlanPoolSource.Add(testFabricVlanPool("aci-containers-system", "default", "[102-105]"))
	agent.fakeNetAttachDefSource.Add(testnetattach("sriov-net-1", "default", configJsondata, resourceAnnot))
	agent.run()

	expected := fabattv1.NodeFabricNetworkAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: nodename + "-default-sriov-net-1",
			Namespace: "aci-containers-system",
		},
		Spec: fabattv1.NodeFabricNetworkAttachmentSpec{
			NetworkRef: fabattv1.ObjRef{
				Name:      "sriov-net-1",
				Namespace: "default",
			},
			EncapVlan: fabattv1.EncapSource{VlanList: "[100,101,195-200]"},
			AciTopology: map[string]fabattv1.AciNodeLinkAdjacency{
				"enp216s0f0": {
					FabricLink: []string{
						"topology/pod-1/node-101/pathep-[eth1/24]",
					},
				},
			},
			NodeName:   nodename,
			PrimaryCNI: "sriov",
		},
	}
	scheme := scheme.Scheme
	fabattv1.AddToScheme(scheme)
	fabAttClient, err := client.New(cfg, client.Options{Scheme: scheme})
	assert.Nil(t, err, "create client")
	actual := &fabattv1.NodeFabricNetworkAttachment{}
	err = fabAttClient.Get(context.TODO(),
		types.NamespacedName{Name: nodename + "-default-sriov-net-1", Namespace: "aci-containers-system"},
		actual,
	)
	assert.Nil(t, err, "nfna create")
	assert.Equal(t, expected.Spec, actual.Spec)
	agent.fakeNetAttachDefSource.Delete(testnetattach("sriov-net-1", "default", configJsondata, resourceAnnot))
	assert.Eventually(t, func() bool {
		err := fabAttClient.Get(context.TODO(),
			types.NamespacedName{Name: nodename + "-default-sriov-net-1", Namespace: "aci-containers-system"},
			actual)
		return err != nil
	}, 5*time.Second, 1*time.Second, "nfna delete")

	err = testenv.Stop()
	assert.Nil(t, err, "envtest stop")
	agent.stop()
}

func TestNADMacVlanCRUD(t *testing.T) {
	testenv := &envtest.Environment{CRDDirectoryPaths: []string{"./testdata"}}
	cfg, err := testenv.Start()
	assert.Nil(t, err, "envtest start")
	kubeClient, err := kubernetes.NewForConfig(cfg)
	assert.Nil(t, err, "clientset create")

	configJsondata := `{"cniVersion": "0.3.1", "name": "macvlan-net2", "plugins":[{"cniVersion": "0.3.1", "name": "macvlan-net2", "type": "macvlan", "mode": "private", "master": "bond1", "ipam": {"type": "whereabouts", "range": "192.168.100.0/24", "exclude": ["192.168.100.0/32", "192.168.100.1/32", "192.168.100.254/32"]}},{ "supportedVersions": [ "0.3.0", "0.3.1", "0.4.0" ], "type": "opflex-agent-cni", "chaining-mode": true, "log-level": "debug", "log-file": "/var/log/opflexagentcni.log" }]}`

	configJsondata2 := `{"cniVersion": "0.3.1", "name": "macvlan-net2", "plugins":[{"cniVersion": "0.3.1", "name": "macvlan-net2", "type": "macvlan", "mode": "private", "master": "bond1.101", "ipam": {"type": "whereabouts", "range": "192.168.100.0/24", "exclude": ["192.168.100.0/32", "192.168.100.1/32", "192.168.100.254/32"]}},{ "supportedVersions": [ "0.3.0", "0.3.1", "0.4.0" ], "type": "opflex-agent-cni", "chaining-mode": true, "log-level": "debug", "log-file": "/var/log/opflexagentcni.log" }]}`
	resourceAnnot := make(map[string]string)
	agent := testAgentEnvtest(getChainedModeConfig(nodename), kubeClient, cfg)
	kubeClient.CoreV1().Namespaces().Create(context.Background(), mkNamespace("aci-containers-system", "", "", ""), metav1.CreateOptions{})
	agent.fakeFabricVlanPoolSource.Add(testFabricVlanPool("aci-containers-system", "default", "[102-105]"))
	agent.fakeNetAttachDefSource.Add(testnetattach("macvlan-net2", "default", configJsondata, resourceAnnot))
	agent.run()

	expected := fabattv1.NodeFabricNetworkAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: nodename + "-default-macvlan-net2",
			Namespace: "aci-containers-system",
		},
		Spec: fabattv1.NodeFabricNetworkAttachmentSpec{
			NetworkRef: fabattv1.ObjRef{
				Name:      "macvlan-net2",
				Namespace: "default",
			},
			EncapVlan: fabattv1.EncapSource{VlanList: "[102-105]"},
			AciTopology: map[string]fabattv1.AciNodeLinkAdjacency{
				"bond1": {
					FabricLink: []string{
						"topology/pod-1/node-101/pathep-[eth1/21]",
						"topology/pod-1/node-102/pathep-[eth1/21]",
					},
				},
			},
			NodeName:   nodename,
			PrimaryCNI: "macvlan",
		},
	}
	scheme := scheme.Scheme
	fabattv1.AddToScheme(scheme)
	fabAttClient, err := client.New(cfg, client.Options{Scheme: scheme})
	assert.Nil(t, err, "create client")
	actual := &fabattv1.NodeFabricNetworkAttachment{}
	err = fabAttClient.Get(context.TODO(),
		types.NamespacedName{Name: nodename + "-default-macvlan-net2", Namespace: "aci-containers-system"},
		actual,
	)
	assert.Nil(t, err, "nfna create")
	assert.Equal(t, expected.Spec.EncapVlan, actual.Spec.EncapVlan)
	assert.Equal(t, expected.Spec.NetworkRef, actual.Spec.NetworkRef)
	expectedLinks := expected.Spec.AciTopology["bond1"].FabricLink
	sort.Strings(expectedLinks)
	actualLinks := actual.Spec.AciTopology["bond1"].FabricLink
	sort.Strings(actualLinks)
	assert.Equal(t, expectedLinks, actualLinks)
	resourceAnnot[vlanAnnot] = "[103-104]"
	agent.fakeNetAttachDefSource.Modify(testnetattach("macvlan-net2", "default", configJsondata2, resourceAnnot))
	assert.Eventually(t, func() bool {
		err = fabAttClient.Get(context.TODO(),
			types.NamespacedName{Name: nodename + "-default-macvlan-net2", Namespace: "aci-containers-system"},
			actual,
		)
		return actual.Spec.EncapVlan == fabattv1.EncapSource{VlanList: "101"}
	}, 5*time.Second, 1*time.Second, "nfna update")
	agent.fakeNetAttachDefSource.Delete(testnetattach("macvlan-net2", "default", configJsondata, resourceAnnot))
	assert.Eventually(t, func() bool {
		err := fabAttClient.Get(context.TODO(),
			types.NamespacedName{Name: nodename + "-macvlan-net2", Namespace: "aci-containers-system"},
			actual)
		return err != nil
	}, 5*time.Second, 1*time.Second, "nfna delete")
	err = testenv.Stop()
	assert.Nil(t, err, "envtest stop")
	agent.stop()
}

func TestNADVlanMatch(t *testing.T) {
	testenv := &envtest.Environment{CRDDirectoryPaths: []string{"./testdata"}}
	cfg, err := testenv.Start()
	assert.Nil(t, err, "envtest start")
	kubeClient, err := kubernetes.NewForConfig(cfg)
	assert.Nil(t, err, "clientset create")

	configJsondata := `{"cniVersion": "0.3.1", "name": "pc-mm-net1", "plugins":[{"cniVersion": "0.3.1", "name": "pc-mm-net1", "type": "macvlan", "mode": "private", "master": "bond1", "ipam": {"type": "whereabouts", "range": "192.168.100.0/24", "exclude": ["192.168.100.0/32", "192.168.100.1/32", "192.168.100.254/32"]}},{ "supportedVersions": [ "0.3.0", "0.3.1", "0.4.0" ], "type": "opflex-agent-cni", "chaining-mode": true, "log-level": "debug", "log-file": "/var/log/opflexagentcni.log" }]}`
	nadVlanMap := &fabattv1.NadVlanMap{
		ObjectMeta: metav1.ObjectMeta{Name: "nad-vlan-map",
			Namespace: "aci-containers-system",
		},
		Spec: fabattv1.NadVlanMapSpec{
			NadVlanMapping: map[string][]fabattv1.VlanSpec{
				"pccmm/pc-mm": {
					{Label: "pc-mm-oam",
						Vlans: "103"}},
			},
		},
	}
	resourceAnnot := make(map[string]string)
	agent := testAgentEnvtest(getChainedModeConfig(nodename), kubeClient, cfg)
	kubeClient.CoreV1().Namespaces().Create(context.TODO(), mkNamespace("aci-containers-system", "", "", ""), metav1.CreateOptions{})
	kubeClient.CoreV1().Namespaces().Create(context.TODO(), mkNamespace("pccmm", "", "", ""), metav1.CreateOptions{})
	scheme := scheme.Scheme
	fabattv1.AddToScheme(scheme)
	fabAttClient, err := client.New(cfg, client.Options{Scheme: scheme})
	assert.Nil(t, err, "create client")
	agent.fakeFabricVlanPoolSource.Add(testFabricVlanPool("aci-containers-system", "default", "[102-105]"))
	agent.fakeNadVlanMapSource.Add(nadVlanMap)
	agent.fakeNetAttachDefSource.Add(testnetattach("pc-mm-net1", "pccmm", configJsondata, resourceAnnot))
	agent.run()

	expected := fabattv1.NodeFabricNetworkAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: nodename + "-pccmm-pc-mm-net1",
			Namespace: "aci-containers-system",
		},
		Spec: fabattv1.NodeFabricNetworkAttachmentSpec{
			NetworkRef: fabattv1.ObjRef{
				Name:      "pc-mm-net1",
				Namespace: "pccmm",
			},
			EncapVlan: fabattv1.EncapSource{
				EncapRef: fabattv1.EncapRef{
					NadVlanMapRef: "aci-containers-system/nad-vlan-map",
					Key:           "pccmm/pc-mm",
				},
				VlanList: "[103]"},
			AciTopology: map[string]fabattv1.AciNodeLinkAdjacency{
				"bond1": {
					FabricLink: []string{
						"topology/pod-1/node-101/pathep-[eth1/21]",
						"topology/pod-1/node-102/pathep-[eth1/21]",
					},
				},
			},
			NodeName:   nodename,
			PrimaryCNI: "macvlan",
		},
	}
	actual := &fabattv1.NodeFabricNetworkAttachment{}
	err = fabAttClient.Get(context.TODO(),
		types.NamespacedName{Name: nodename + "-pccmm-pc-mm-net1", Namespace: "aci-containers-system"},
		actual,
	)
	assert.Nil(t, err, "nfna create")
	assert.Equal(t, expected.Spec.EncapVlan, actual.Spec.EncapVlan)
	assert.Equal(t, expected.Spec.NetworkRef, actual.Spec.NetworkRef)
	expectedLinks := expected.Spec.AciTopology["bond1"].FabricLink
	sort.Strings(expectedLinks)
	actualLinks := actual.Spec.AciTopology["bond1"].FabricLink
	sort.Strings(actualLinks)
	assert.Equal(t, expectedLinks, actualLinks)
	nadVlanMap.Spec.NadVlanMapping["pccmm/pc-mm"][0].Vlans = "104"
	agent.fakeNadVlanMapSource.Modify(nadVlanMap)
	agent.fakeFabricVlanPoolSource.Add(testFabricVlanPool("aci-containers-system", "default", "[102-105]"))
	expected.Spec.EncapVlan = fabattv1.EncapSource{
		EncapRef: fabattv1.EncapRef{
			NadVlanMapRef: "aci-containers-system/nad-vlan-map",
			Key:           "pccmm/pc-mm",
		},
		VlanList: "[104]",
	}
	assert.Eventually(t, func() bool {
		fabAttClient.Get(context.TODO(),
			types.NamespacedName{Name: nodename + "-pccmm-pc-mm-net1", Namespace: "aci-containers-system"},
			actual)
		return reflect.DeepEqual(expected.Spec.EncapVlan, actual.Spec.EncapVlan)
	}, 5*time.Second, 1*time.Second, "nadvlanmap update")

	agent.fakeNadVlanMapSource.Delete(nadVlanMap)
	expected.Spec.EncapVlan = fabattv1.EncapSource{
		VlanList: "[102-105]",
	}
	assert.Eventually(t, func() bool {
		fabAttClient.Get(context.TODO(),
			types.NamespacedName{Name: nodename + "-pccmm-pc-mm-net1", Namespace: "aci-containers-system"},
			actual)
		agent.log.Debugf("Actual vlan:%s", actual.Spec.EncapVlan)
		return reflect.DeepEqual(expected.Spec.EncapVlan, actual.Spec.EncapVlan)
	}, 5*time.Second, 1*time.Second, "nadvlanmap delete")

	agent.fakeNetAttachDefSource.Delete(testnetattach("pc-mm-net1", "pccmm", configJsondata, resourceAnnot))
	assert.Eventually(t, func() bool {
		err := fabAttClient.Get(context.TODO(),
			types.NamespacedName{Name: nodename + "-pccmm-pc-mm-net1", Namespace: "aci-containers-system"},
			actual)
		return err != nil
	}, 5*time.Second, 1*time.Second, "nfna delete")
	err = testenv.Stop()
	assert.Nil(t, err, "envtest stop")
	agent.stop()
}

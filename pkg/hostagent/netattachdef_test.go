package hostagent

import (
	netpolicy "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
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
	agent.fakeNetAttachDefSource.Add(testnetattach("default", "kube-system", configJsondata, resourceAnnot))
	agent.run()

	actual := &NetworkAttachmentData{
		Name:      "default",
		Namespace: "kube-system",
		Config:    configJsondata,
		Annot:     "mellanox.com/cx5_sriov_switchdev",
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
	agent.fakeNetAttachDefSource.Add(testnetattach("default", "kube-system", configJsondata, resourceAnnot))
	agent.run()

	var actual *NetworkAttachmentData
	delete(agent.netattdefmap, "default")
	expected := agent.netattdefmap["default"]
	assert.Equal(t, actual, expected)
}

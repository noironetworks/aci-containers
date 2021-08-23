package controller

import (
        snatglobalinfo "github.com/noironetworks/aci-containers/pkg/snatglobalinfo/apis/aci.snat/v1"
        "k8s.io/api/core/v1"
        metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
        "testing"
        "time"
	"fmt"
	"strings"
	"strconv"
)

var nodeTestsOld = []nodedata{
        {
                "testns",
                "node-2",
                map[string]bool{"policy1": true, "policy2": true},
                "01:02:03:05",
        },
        {
                "testns",
                "node-1",
                map[string]bool{"policy2": true, "policy1": true},
                "01:02:03:04",
        },
}


func createNodeInfo(start int, end int, nodeData []nodedata) {
//	nodeData := make([]nodedata, 100)
	for i := start; i <= end; i++ {
		nodeData[i] = nodedata{"testns",
strings.Join([]string{"node-", strconv.Itoa(i)}, ""),
map[string]bool{"policy1": true, "policy2": true},
strings.Join([]string{"01:02:03:", strconv.Itoa(i)}, "") }
	}
	fmt.Println(nodeData)
//	return nodeData
}

var nodeTestsNew = []nodedata{
        {
                "testns",
                "node-3",
                map[string]bool{"policy2": true, "policy1": true},
                "01:02:03:06",
        },
        {
                "testns",
                "node-4",
                map[string]bool{"policy2": true, "policy1": true},
                "01:02:03:07",
        },
}

var snatTestsNew = []policy{
        {
                "testns",
                "policy2",
                []string{"10.1.1.9"},
                map[string]string{"key": "value"},
        },
}

func TestSnatPortExhaustion(t *testing.T) {
        cont := testController()
        for _, pt := range snatTestsNew {
                snatObj := snatpolicydata(pt.name, pt.namespace, pt.snatip, pt.labels)
                cont.fakeSnatPolicySource.Add(snatObj)
        }
        cont.run()
        nodinfo := make(map[string]bool)
        configmap := &v1.ConfigMap{
                Data: map[string]string{"start": "5000", "end": "10000", "ports-per-node": "3000"},
                ObjectMeta: metav1.ObjectMeta{
                        Name:      "snat-operator-config",
                        Namespace: "aci-containers-system",
                },
        }
        cont.fakeSnatCfgSource.Add(configmap)
	nodeData := make([]nodedata, 22)
	initialLength := 17
	newLength := 21
        //for _, pt := range nodeTestsOld {
	createNodeInfo(1,initialLength, nodeData)
	for _, pt := range nodeData{
                nodeobj := Nodeinfodata(pt.name, pt.namespace, pt.macaddr, pt.snatpolicynames)
                if _, ok := nodinfo[pt.name]; !ok {
                        cont.fakeNodeInfoSource.Add(nodeobj)
                        cont.log.Debug("NodeInfo Added: ", nodeobj)
                        nodinfo[pt.name] = true
                } else {
                        cont.log.Debug("NodeInfo Modified: ", nodeobj)
                        cont.fakeNodeInfoSource.Modify(nodeobj)
                }
        }
        time.Sleep(time.Millisecond * 500)
        modconfigmap := &v1.ConfigMap{
                Data: map[string]string{"start": "5000", "end": "65000", "ports-per-node": "3000"},
                ObjectMeta: metav1.ObjectMeta{
                        Name:      "snat-operator-config",
                        Namespace: "aci-containers-system",
                },
        }
        cont.fakeSnatCfgSource.Modify(modconfigmap)
        time.Sleep(time.Millisecond * 100)
	oldResults := make(map[string]snatglobalinfo.PortRange)

	for i := range nodeData {
		if i >= initialLength {
			break
		}
		newNodeName := strings.Join([]string{"node-", strconv.Itoa(i+1)}, "")
		oldResults[newNodeName] = cont.AciController.snatGlobalInfoCache["10.1.1.9"][newNodeName].PortRanges[0]
	}

        cont.log.Info("heyyy",cont.AciController.snatGlobalInfoCache["10.1.1.9"]["node-1"])
	createNodeInfo(initialLength+1, newLength, nodeData)

	for _, pt := range nodeData{
                nodeobj := Nodeinfodata(pt.name, pt.namespace, pt.macaddr, pt.snatpolicynames)
                if _, ok := nodinfo[pt.name]; !ok {
                        cont.fakeNodeInfoSource.Add(nodeobj)
                        cont.log.Debug("NodeInfo Added: ", nodeobj)
                        nodinfo[pt.name] = true
                } else {
                        cont.log.Debug("NodeInfo Modified: ", nodeobj)
                        cont.fakeNodeInfoSource.Modify(nodeobj)
                }
        }
        time.Sleep(time.Millisecond * 500)
	results := make(map[string]snatglobalinfo.PortRange)

	for i := initialLength+1; i < newLength; i++ {
		newNodeName := strings.Join([]string{"node-", strconv.Itoa(i+1)}, "")
		//fmt.Println(i)
		if _, ok := cont.AciController.snatGlobalInfoCache["10.1.1.9"][newNodeName]; !ok {
			cont.log.Info("No port allocated for ---------- ", newNodeName)
			continue
		}
		results[newNodeName] = cont.AciController.snatGlobalInfoCache["10.1.1.9"][newNodeName].PortRanges[0]
	}
	cont.log.Info("heyyy",cont.AciController.snatGlobalInfoCache["10.1.1.9"]["node-1"])
	//cont.log.Info("heyyy",cont.AciController.snatGlobalInfoCache["10.1.1.9"]["node-3"])
	//cont.log.Info("heyyy",cont.AciController.snatGlobalInfoCache["10.1.1.9"]["node-4"])
        //time.Sleep(time.Millisecond * 500)

	/*for _, pt := range nodeTestsNew {
                nodeobj := Nodeinfodata(pt.name, pt.namespace, pt.macaddr, pt.snatpolicynames)
                if _, ok := nodinfo[pt.name]; !ok {
                        cont.fakeNodeInfoSource.Add(nodeobj)
                        cont.log.Debug("NodeInfo Added: ", nodeobj)
                        nodinfo[pt.name] = true
                } else {
                        cont.log.Debug("NodeInfo Modified: ", nodeobj)
                        cont.fakeNodeInfoSource.Modify(nodeobj)
                }
        }

	time.Sleep(time.Millisecond * 500)


	cont.log.Info("heyyy",cont.AciController.snatGlobalInfoCache["10.1.1.9"]["node-1"])
        cont.log.Info("heyyy",cont.AciController.snatGlobalInfoCache["10.1.1.9"]["node-2"])
        cont.log.Info("heyyy",cont.AciController.snatGlobalInfoCache["10.1.1.9"]["node-3"])
        cont.log.Info("heyyy",cont.AciController.snatGlobalInfoCache["10.1.1.9"]["node-4"])

	for _, pt := range nodeTestsNew {
                nodeobj := Nodeinfodata(pt.name, pt.namespace, pt.macaddr, pt.snatpolicynames)
                if _, ok := nodinfo[pt.name]; !ok {
                        cont.fakeNodeInfoSource.Delete(nodeobj)
                        cont.log.Debug("NodeInfo Added: ", nodeobj)
                        nodinfo[pt.name] = true
                } else {
                        cont.log.Debug("NodeInfo Modified: ", nodeobj)
                        cont.fakeNodeInfoSource.Delete(nodeobj)
                }
        }

        time.Sleep(time.Millisecond * 500)

        cont.log.Info("heyyy",cont.AciController.snatGlobalInfoCache["10.1.1.9"]["node-1"])
        cont.log.Info("heyyy",cont.AciController.snatGlobalInfoCache["10.1.1.9"]["node-2"])
        cont.log.Info("heyyy",cont.AciController.snatGlobalInfoCache["10.1.1.9"]["node-3"])
        cont.log.Info("heyyy",cont.AciController.snatGlobalInfoCache["10.1.1.9"]["node-4"])
	*/
        cont.stop()
}

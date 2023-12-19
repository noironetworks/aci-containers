package controller

import (
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	apicapi "github.com/noironetworks/aci-containers/pkg/apicapi"
	fabattv1 "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
	"github.com/noironetworks/aci-containers/pkg/util"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func TestCombineVlanPools(t *testing.T) {
	nsVlanPoolMap1 := map[string]map[string]string{
		"aci-containers-system": {
			"default":    "[3023,3700-3701,3801,3804-3805,3826-3827,3829-3830,3840,3850-3852,3877-3879]",
			"additional": "[100]",
		},
		"default": {
			"test":       "[610]",
			"additional": "[3000]",
		},
	}
	combinedStr1 := util.CombineVlanPoolMaps(nsVlanPoolMap1, "aci-containers-system")
	elems := strings.Split(combinedStr1, ",")
	expectedStr1 := "3023,3700-3701,3801,3804-3805,3826-3827,3829-3830,3840,3850-3852,3877-3879,100"
	expectedElems := strings.Split(expectedStr1, ",")
	assert.Equal(t, len(elems), len(expectedElems), "namespace pool collect 1")

	combinedStr2 := util.CombineVlanPoolMaps(nsVlanPoolMap1, "default")
	elems = strings.Split(combinedStr2, ",")
	expectedStr2 := "610,3000"
	expectedElems = strings.Split(expectedStr2, ",")
	assert.Equal(t, len(elems), len(expectedElems), "namespace pool collect 2")

	combinedStr3 := util.CombineVlanPoolMaps(nsVlanPoolMap1, "")
	elems = strings.Split(combinedStr3, ",")
	expectedStr3 := "3023,3700-3701,3801,3804-3805,3826-3827,3829-3830,3840,3850-3852,3877-3879,100,610,3000"
	expectedElems = strings.Split(expectedStr3, ",")
	assert.Equal(t, len(elems), len(expectedElems), "global pool collect")
}

func fabricVlanPool() *fabattv1.FabricVlanPool {
	fabVlanPool := &fabattv1.FabricVlanPool{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: fabattv1.FabricVlanPoolSpec{
			Vlans: []string{"610", "3000"},
		},
	}
	return fabVlanPool
}

func fabricPoolInformerInit(cont *testAciController) {
	go cont.fabricVlanPoolInformer.Run(cont.stopCh)
	go cont.processQueue(cont.fabricVlanPoolQueue, cont.fabricVlanPoolInformer.GetIndexer(),
		func(obj interface{}) bool {
			return cont.handleFabricVlanPoolUpdate(obj)
		}, func(key string) bool {
			return cont.handleFabricVlanPoolDelete(key)
		}, nil, cont.stopCh)
}

func fabVlanPoolWait(t *testing.T, desc string, cont *testAciController,
	key string, isexpected string, present bool, expected apicapi.ApicObject) {
	tu.WaitFor(t, desc, 500*time.Millisecond,
		func(last bool) (bool, error) {
			cont.indexMutex.Lock()
			defer cont.indexMutex.Unlock()
			var ok bool
			ds := cont.apicConn.GetDesiredState(key)
			for _, v := range ds {
				if _, ok = v[isexpected]; ok {
					if cmp.Equal(*v[isexpected], *expected[isexpected]) == true {
						ok = true
					} else {
						ok = false
					}
					break
				}
			}
			if ok == present {
				return true, nil
			}
			return false, nil
		})
	cont.log.Info("Finished waiting for ", desc)
}

func TestFabricVlanPool(t *testing.T) {
	fabVlanPool := fabricVlanPool()
	cont := testController()
	cont.config.AciUseGlobalScopeVlan = true
	cont.run()
	defer cont.stop()
	fabricPoolInformerInit(cont)
	cont.fakeFabricVlanPoolsSource.Add(fabVlanPool)
	labelKey := cont.aciNameForKey("nfna", "secondary")
	fvnsVlanInstP := apicapi.NewFvnsVlanInstP(cont.config.AciPolicyTenant, "secondary")
	fvnsVlanInstP.SetAttr("annotation", "orchestrator:aci-containers-controller")
	fvnsEncapBlk := apicapi.NewFvnsEncapBlk(fvnsVlanInstP.GetDn(), "3000", "3000")
	fvnsEncapBlk.SetAttr("annotation", "orchestrator:aci-containers-controller")
	fvnsVlanInstP.AddChild(fvnsEncapBlk)
	fvnsEncapBlk = apicapi.NewFvnsEncapBlk(fvnsVlanInstP.GetDn(), "610", "610")
	fvnsEncapBlk.SetAttr("annotation", "orchestrator:aci-containers-controller")
	fvnsVlanInstP.AddChild(fvnsEncapBlk)

	fabVlanPoolWait(t, "FabricVlanPool added", cont, labelKey, "fvnsVlanInstP", true, fvnsVlanInstP)

	cont.fakeFabricVlanPoolsSource.Delete(fabVlanPool)
	fvnsVlanInstPDel := apicapi.NewFvnsVlanInstP(cont.config.AciPolicyTenant, "secondary")
	fvnsVlanInstPDel.SetAttr("annotation", "orchestrator:aci-containers-controller")

	fabVlanPoolWait(t, "FabricVlanPool deleted", cont, labelKey, "fvnsVlanInstP", true, fvnsVlanInstPDel)

	cont.fakeFabricVlanPoolsSource.Modify(fabVlanPool)
	fabVlanPoolWait(t, "FabricVlanPool Added", cont, labelKey, "fvnsVlanInstP", true, fvnsVlanInstP)

	type test struct {
		metav1.ObjectMeta
	}

	fakeFabricVlanPool := &test{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "test",
		},
	}
	cont.fabricVlanPoolDeleted(fakeFabricVlanPool)
	time.Sleep(100 * time.Millisecond)

	fabVlanPoolWait(t, "FabricVlanPool Should not be deleted", cont, labelKey, "fvnsVlanInstP", true, fvnsVlanInstP)

	fakeFabricVlanPool2 := cache.DeletedFinalStateUnknown{
		Key: "key",
		Obj: labelKey,
	}

	cont.fabricVlanPoolDeleted(fakeFabricVlanPool2)
	time.Sleep(100 * time.Millisecond)

	fabVlanPoolWait(t, "FabricVlanPool Should not be deleted", cont, labelKey, "fvnsVlanInstP", true, fvnsVlanInstP)

	cont.fabricVlanPoolDeleted(fabVlanPool)
	time.Sleep(100 * time.Millisecond)

	fabVlanPoolWait(t, "FabricVlanPool deleted", cont, labelKey, "fvnsVlanInstP", true, fvnsVlanInstPDel)

}

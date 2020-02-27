package metrics

import (
	"fmt"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	"math/rand"
	"testing"
	"time"
	//log "github.com/sirupsen/logrus"
)

func injectSvcUpdate(obj *PodStatsObj, ns, name, clusterIP string, port, epPort int32, epAddr []string) {
	s := &v1.Service{
		Spec: v1.ServiceSpec{
			ClusterIP: clusterIP,
			Ports: []v1.ServicePort{
				{
					Port: port,
				},
			},
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
		},
	}

	ssAddr := []v1.EndpointAddress{}
	for _, addr := range epAddr {
		var a *v1.EndpointAddress
		a = new(v1.EndpointAddress)
		a.IP = addr
		ssAddr = append(ssAddr, *a)
	}
	eps := &v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
		},
		Subsets: []v1.EndpointSubset{
			{
				Addresses: ssAddr,
				Ports: []v1.EndpointPort{
					{
						Port: epPort,
					},
				},
			},
		},
	}
	obj.SvcUpdate(s, eps, true)
}

func injectPod(obj *PodStatsObj, ns, name, uuid string, labels map[string]string) {
	pod := &v1.Pod{
		Spec: v1.PodSpec{},
		ObjectMeta: metav1.ObjectMeta{
			UID:       apitypes.UID(uuid),
			Namespace: ns,
			Name:      name,
			Labels:    labels,
		},
	}

	obj.UpdatePodMeta(pod, false)
}

func getIds(count int) map[int]bool {
	res := make(map[int]bool)
	for {
		res[rand.Intn(9)] = true
		if len(res) == count {
			return res
		}
	}
}
func TestMetrics(t *testing.T) {
	sObj := NewPodStats()
	go InitPromExporter(sObj, ":8091")
	//inject some services and pods
	for ix := 0; ix < 10; ix++ {
		svc := fmt.Sprintf("svc-%d", ix)
		clusterIP := fmt.Sprintf("10.96.1.%d", 100+ix)
		ep1 := fmt.Sprintf("10.1.11.%d", ix)
		ep2 := fmt.Sprintf("10.1.12.%d", ix)
		injectSvcUpdate(sObj, "default", svc, clusterIP, int32(8888+ix), int32(10888+ix), []string{ep1, ep2})
	}

	for ix := 0; ix < 10; ix++ {
		appTag := fmt.Sprintf("app-%d", ix)
		depTag := fmt.Sprintf("depl-%d", ix)
		podLabels := map[string]string{
			"app":        appTag,
			"deployment": depTag,
		}
		podName := fmt.Sprintf("pod-%d", ix)
		podUid := fmt.Sprintf("730a8e7a-8455-4d46-8e6e-f4fdf0e3a%30d", ix)
		injectPod(sObj, "default", podName, podUid, podLabels)
	}

	// Establish random connectivity
	conns := make(map[string][]Tuple)

	for ix := 0; ix < 10; ix++ {
		podUid := fmt.Sprintf("730a8e7a-8455-4d46-8e6e-f4fdf0e3a%30d", ix)
		// each pod connects to 1-6 services
		count := rand.Intn(5) + 1
		svcList := make([]Tuple, 0, count)
		idSet := getIds(count)
		for id := range idSet {
			clusterIP := fmt.Sprintf("10.96.1.%d", 100+id)
			dPort := fmt.Sprintf("%d", 8888+id)
			tuple := Tuple{
				prot:     "tcp",
				srcIP:    "10.1.1.2",
				srcPort:  "20111",
				destIP:   clusterIP,
				destPort: dPort,
			}

			svcList = append(svcList, tuple)
		}

		conns[podUid] = svcList
	}

	stopCh := make(chan bool)
	go func() {
		for {
			select {
			case <-stopCh:
				return
			case <-time.After(2 * time.Second):
				id := rand.Intn(9)
				podUid := fmt.Sprintf("730a8e7a-8455-4d46-8e6e-f4fdf0e3a%30d", id)
				svcList := conns[podUid]
				svcId := rand.Intn(len(svcList))
				if svcId == len(svcList) {
					svcId = svcId - 1
				}
				statRec := StatsRec{
					connections: rand.Intn(999),
					bytes:       rand.Intn(25000),
					packets:     rand.Intn(3300),
					timestamp:   time.Now(),
				}
				sObj.StatsUpdate(podUid, svcList[svcId], statRec, "egress")
			}
		}
	}()

	<-time.After(600 * time.Second)
	close(stopCh)
}

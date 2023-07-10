package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/golang/glog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	aciawclientset "github.com/noironetworks/aci-containers/pkg/gbpcrd/clientset/versioned"
)

var (
	kuberconfig = flag.String("kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	master      = flag.String("master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
)

func main() {
	flag.Parse()

	cfg, err := clientcmd.BuildConfigFromFlags(*master, *kuberconfig)
	if err != nil {
		glog.Fatalf("Error building kubeconfig: %v", err)
	}

	aciawClient, err := aciawclientset.NewForConfig(cfg)
	if err != nil {
		glog.Fatalf("Error building aciaw clientset: %v", err)
	}

	list, err := aciawClient.AciV1().Epgs("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		glog.Fatalf("Error listing all epgs: %v", err)
	}

	for i := range list.Items {
		fmt.Printf("Epg %+v \n", list.Items[i])
	}

	cList, err := aciawClient.AciV1().Contracts("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		glog.Fatalf("Error listing all contracts: %v", err)
	}

	for i := range cList.Items {
		fmt.Printf("Contract %+v \n", cList.Items[i])
	}
}

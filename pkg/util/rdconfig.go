package util

import (
	"context"
	"os"

	rdConfig "github.com/noironetworks/aci-containers/pkg/rdconfig/apis/aci.snat/v1"
	rdconfigclset "github.com/noironetworks/aci-containers/pkg/rdconfig/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CreateRdConfigCR creates a RdConfig CR
func CreateRdConfigCR(r rdconfigclset.Clientset, rdConfigSpec rdConfig.RdConfigSpec) error {
	ns := os.Getenv("ACI_SNAT_NAMESPACE")
	name := os.Getenv("ACI_RDCONFIG_NAME")
	rdConfigInstance := &rdConfig.RdConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: rdConfigSpec,
	}
	_, err := r.AciV1().RdConfigs(ns).Create(context.TODO(), rdConfigInstance, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

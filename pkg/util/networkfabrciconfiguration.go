package util

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	nfc "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment/v1"
	nfcclset "github.com/noironetworks/aci-containers/pkg/fabricattachment/clientset/versioned"
)

func UpdateNfcCR(c nfcclset.Clientset, nfc *nfc.NetworkFabricConfiguration) error {
	_, err := c.AciV1().NetworkFabricConfigurations().UpdateStatus(context.TODO(), nfc, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}
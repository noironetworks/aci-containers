package cmd

import (
	"bytes"
	kubecontext "context"
	"fmt"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
	"strings"
)

func processpolicy(cmd *cobra.Command, args []string) {
	// Extract the arguments
	req := args[0]

	kubeClient := initClientPrintError()
	if kubeClient == nil {
		return
	}
	systemNamespace, err := findSystemNamespace(kubeClient)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not find aci-containers system namespace:", err)
		return
	}

	systemNamespacePods, err1 := kubeClient.CoreV1().Pods(systemNamespace).List(kubecontext.TODO(), metav1.ListOptions{})
	if err1 != nil {
		fmt.Fprintln(os.Stderr, "Could not list pods:", err1)
	}

	// Check again in kube-system
	if len(systemNamespacePods.Items) == 0 {
		systemNamespace = "kube-system"
		systemNamespacePods, err1 = kubeClient.CoreV1().Pods(systemNamespace).List(kubecontext.TODO(), metav1.ListOptions{})
	}
	if err1 != nil {
		fmt.Fprintln(os.Stderr, "Could not list pods:", err1)
	}

	if req == "store" {
		for pod := range systemNamespacePods.Items {
			if strings.Contains(systemNamespacePods.Items[pod].Name, "aci-containers-host") {
				buffer := new(bytes.Buffer)
				path := "/usr/local/var/lib/opflex-agent-ovs/startup/pol.json"
				execCmd := fmt.Sprintf("gbp_inspect -fprq DmtreeRoot -t dump > %s", path)
				podName := systemNamespacePods.Items[pod].Name
				cmd := []string{"exec", podName, "-n", systemNamespace, "-c", "opflex-agent", "--", "bash", "-c", execCmd}
				fmt.Println("execute command :", cmd)
				execKubectl(cmd, buffer)
				if buffer != nil {
					trimString := strings.TrimSpace(buffer.String())
					fmt.Println(trimString)
				}
			}
		}
	} else if req == "remove" {
		for pod := range systemNamespacePods.Items {
			if strings.Contains(systemNamespacePods.Items[pod].Name, "aci-containers-host") {
				buffer := new(bytes.Buffer)
				execCmd := "rm /usr/local/var/lib/opflex-agent-ovs/startup/pol.json"
				podName := systemNamespacePods.Items[pod].Name
				cmd := []string{"exec", podName, "-n", systemNamespace, "-c", "opflex-agent", "--", "bash", "-c", execCmd}
				fmt.Println("execute command :", cmd)
				execKubectl(cmd, buffer)
				if buffer != nil {
					trimString := strings.TrimSpace(buffer.String())
					fmt.Println(trimString)
				}
			}
		}
	} else {
		fmt.Fprintln(os.Stderr, "Could not process the request: Invalid input")
	}
}

var policyDumpCmd = &cobra.Command{
	Use:     "policy store/remove",
	Short:   "output the gbp_inspect policies into a file for all the host-agent pods",
	Example: `acikubectl policy store/remove`,
	Args:    cobra.ExactArgs(1),
	Run:     processpolicy,
}

func init() {
	RootCmd.AddCommand(policyDumpCmd)
}

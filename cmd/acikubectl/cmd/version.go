// Copyright © 2019 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"bytes"
	"fmt"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
	"strings"
)

func getVersion(cmd *cobra.Command, args []string) {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "More arguments than required")
		return
	}
	kubeClient := initClientPrintError()
	if kubeClient == nil {
		return
	}
	systemNamespace, err := findSystemNamespace(kubeClient)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not find aci-containers system namespace:", err)
		return
	}
	systemNamespacePods, err1 := kubeClient.CoreV1().Pods(systemNamespace).List(metav1.ListOptions{})
	if err1 != nil {
		fmt.Fprintln(os.Stderr, "Could not list pods:", err1)
	}
	for _, pod := range systemNamespacePods.Items {
		if strings.Contains(pod.Name, "aci-containers-controller") {
			buffer := new(bytes.Buffer)
			mylist := []string{"exec", "-n" + systemNamespace, pod.Name, "--", "/bin/sh", "-c", "aci-containers-controller -version"}
			execKubectl(mylist, buffer)
			trimString := strings.TrimSpace(buffer.String())
			fmt.Println(trimString)
			break
		}
	}
}

var versionCmd = &cobra.Command{
	Use:     "version",
	Short:   "Print the client and server versions for the current context acikubectl version",
	Example: `acikubectl version`,
	Run:     getVersion,
}

func init() {
	RootCmd.AddCommand(versionCmd)
}

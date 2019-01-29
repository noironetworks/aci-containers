// Copyright © 2017 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/spf13/cobra"
)

func execKubectl(args []string, out io.Writer) error {
	baseargs := []string{"--kubeconfig", kubeconfig, "--context", context}
	cmd := exec.Command("kubectl", append(baseargs, args...)...)

	cmd.Stdout = out
	cmd.Stderr = os.Stderr

	err := cmd.Start()
	if err != nil {
		return err
	}
	cmd.Wait()
	return nil
}

type reportCmdElem struct {
	name string
	args []string
}

type reportNodeCmd struct {
	path     string
	cont     string
	selector string
	args     []string
	argFunc  nodeCmdArgFunc
}

func clusterReport(cmd *cobra.Command, args []string) {
	output, err := cmd.PersistentFlags().GetString("output")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if output == "" {
		fmt.Fprintln(os.Stderr, "Output file not specified (use --output)")
		return
	}

	kubeClient := initClientPrintError()
	if kubeClient == nil {
		return
	}

	systemNamespace, err := findSystemNamespace(kubeClient)
	if err != nil {
		fmt.Fprintln(os.Stderr,
			"Could not find aci-containers system namespace:", err)
		return
	}

	cmds := []reportCmdElem{
		{
			name: "cluster-report/logs/controller/acc.log",
			args: accLogCmdArgs(systemNamespace),
		},
		{
			name: "cluster-report/status/describe_nodes_status.log",
			args: []string{"-n", systemNamespace, "describe", "nodes"},
		},
		{
			name: "cluster-report/status/controller_deployment_status.log",
			args: []string{"-n", systemNamespace, "describe", "deployment",
				"aci-containers-controller"},
		},
		{
			name: "cluster-report/status/host_daemonset_status.log",
			args: []string{"-n", systemNamespace, "describe", "daemonset",
				"aci-containers-host"},
		},
		{
			name: "cluster-report/status/ovs_daemonset_status.log",
			args: []string{"-n", systemNamespace, "describe", "daemonset",
				"aci-containers-openvswitch"},
		},
		{
			name: "cluster-report/status/pods_status.log",
			args: []string{"get", "pods", "--all-namespaces", "--include-uninitialized"},
		},
		{
			name: "cluster-report/status/services_status.log",
			args: []string{"get", "services", "--all-namespaces", "--include-uninitialized"},
		},
		{
			name: "cluster-report/status/cluster-info.log",
			args: []string{"cluster-info"},
		},
	}

	nodes, err :=
		kubeClient.CoreV1().Nodes().List(metav1.ListOptions{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not list nodes:", err)
	}

	nodeItems := []reportNodeCmd{
		{
			path:     "cluster-report/logs/node-%s/opflex-agent.log",
			cont:     "opflex-agent",
			selector: opflexAgentSelector,
			argFunc:  nodeLogCmdArgs,
		},
		{
			path:     "cluster-report/logs/node-%s/aci-containers-host.log",
			cont:     "aci-containers-host",
			selector: hostAgentSelector,
			argFunc:  nodeLogCmdArgs,
		},
		{
			path:     "cluster-report/logs/node-%s/aci-containers-openvswitch.log",
			cont:     "aci-containers-openvswitch",
			selector: openvswitchSelector,
			argFunc:  nodeLogCmdArgs,
		},
		{
			path:     "cluster-report/cmds/node-%s/gbp-inspect.log",
			cont:     "opflex-agent",
			selector: opflexAgentSelector,
			argFunc:  inspectArgs,
			args:     []string{"-rfpq", "DmtreeRoot", "-t", "dump"},
		},
		{
			path:     "cluster-report/cmds/node-%s/ovs-ofctl-dump-flows-int.log",
			cont:     "aci-containers-openvswitch",
			selector: openvswitchSelector,
			argFunc:  ovsOfCtlArgs,
			args:     []string{"dump-flows", "br-int"},
		},
		{
			path:     "cluster-report/cmds/node-%s/ovs-ofctl-dump-flows-access.log",
			cont:     "aci-containers-openvswitch",
			selector: openvswitchSelector,
			argFunc:  ovsOfCtlArgs,
			args:     []string{"dump-flows", "br-access"},
		},
		{
			path:     "cluster-report/cmds/node-%s/ovs-vsctl-show.log",
			cont:     "aci-containers-openvswitch",
			selector: openvswitchSelector,
			argFunc:  ovsVsCtlArgs,
			args:     []string{"show"},
		},
		{
			path:     "cluster-report/cmds/node-%s/ip-a.log",
			cont:     "aci-containers-openvswitch",
			selector: openvswitchSelector,
			argFunc:  otherNodeArgs,
			args:     []string{"ip", "a"},
		},
		{
			path:     "cluster-report/cmds/node-%s/ip-r.log",
			cont:     "aci-containers-openvswitch",
			selector: openvswitchSelector,
			argFunc:  otherNodeArgs,
			args:     []string{"ip", "r"},
		},
	}

	nodePodMap := make(map[string]string)

	for _, node := range nodes.Items {
		for _, nodeItem := range nodeItems {
			key := node.Name + ";" + nodeItem.selector
			podName, cached := nodePodMap[key]
			if !cached {
				podName, err = podForNode(kubeClient, systemNamespace,
					node.Name, nodeItem.selector)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					continue
				}
			}

			cmds = append(cmds, reportCmdElem{
				name: fmt.Sprintf(nodeItem.path, node.Name),
				args: nodeItem.argFunc(systemNamespace, podName,
					nodeItem.cont, nodeItem.args),
			})
		}
	}
	output, outfile, err := getOutfile(output)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer outfile.Close()

	gzWriter := gzip.NewWriter(outfile)
	tarWriter := tar.NewWriter(gzWriter)
	now := time.Now()
	hasErrors := false

	// Execute kubectl commands
	for _, cmd := range cmds {
		buffer := new(bytes.Buffer)

		fmt.Fprintln(os.Stderr, "Running command: kubectl", strings.Join(cmd.args, " "))
		err := execKubectl(cmd.args, buffer)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			hasErrors = true
			continue
		}

		tarWriter.WriteHeader(&tar.Header{
			Name:    cmd.name,
			Mode:    0644,
			ModTime: now,
			Size:    int64(buffer.Len()),
		})
		buffer.WriteTo(tarWriter)
	}

	tarWriter.Close()
	gzWriter.Close()

	if hasErrors {
		fmt.Fprintln(os.Stderr, "Wrote report (with errors) to", output)
	} else {
		fmt.Fprintln(os.Stderr, "Finished writing report to", output)
	}
}

func getOutfile(output string) (string, *os.File, error) {
	if output == "-" {
		return "standard output", os.Stdout, nil
	} else {
		outfile, err := os.Create(output)
		if err != nil {
			return output, nil, err
		}
		return output, outfile, nil
	}
}

func outputCmd(cmd *cobra.Command, cmdArgs []string) {
	output, err := cmd.PersistentFlags().GetString("output")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	outfile := os.Stdout
	if output != "" {
		outfile, err := os.Create(output)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		defer outfile.Close()
	}
	err = execKubectl(cmdArgs, outfile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func accLogCmdArgs(systemNamespace string) []string {
	return []string{"-n", systemNamespace, "logs", "--limit-bytes=10048576",
		"deployment/aci-containers-controller",
		"-c", "aci-containers-controller"}
}

type nodeCmdArgFunc func(string, string, string, []string) []string

func nodeLogCmdArgs(systemNamespace string, podName string,
	containerName string, args []string) []string {

	return []string{"-n", systemNamespace, "logs", "--limit-bytes=10048576",
		podName, "-c", containerName}
}

func findSystemNamespace(kubeClient kubernetes.Interface) (string, error) {
	opts := metav1.ListOptions{
		LabelSelector: namespaceSelector,
	}
	namespaces, err :=
		kubeClient.CoreV1().Namespaces().List(opts)
	if err != nil {
		return "", err
	}
	for _, namespace := range namespaces.Items {
		return namespace.Name, nil
	}
	return "kube-system", nil
}

func podForNode(kubeClient kubernetes.Interface,
	systemNamespace string, node string, selector string) (string, error) {
	opts := metav1.ListOptions{
		LabelSelector: selector,
	}
	pods, err :=
		kubeClient.CoreV1().Pods(systemNamespace).List(opts)
	if err != nil {
		return "", err
	}
	for _, pod := range pods.Items {
		if pod.Spec.NodeName == node {
			return pod.Name, nil
		}
	}
	return "", errors.New("Could not find pod on node: " + node)
}

const namespaceSelector = "network-plugin=aci-containers"
const opflexAgentSelector = "network-plugin=aci-containers,name=aci-containers-host"
const hostAgentSelector = "network-plugin=aci-containers,name=aci-containers-host"
const openvswitchSelector = "network-plugin=aci-containers,name=aci-containers-openvswitch"

func inspectArgs(systemNamespace string, podName string,
	containerName string, args []string) []string {
	return append([]string{"-n", systemNamespace, "exec",
		podName, "-c", containerName, "--", "gbp_inspect"}, args...)
}

func ovsVsCtlArgs(systemNamespace string, podName string, containerName string,
	args []string) []string {
	return append([]string{"-n", systemNamespace, "exec",
		podName, "-c", containerName, "--", "ovs-vsctl"}, args...)
}

func ovsOfCtlArgs(systemNamespace string, podName string, containerName string,
	args []string) []string {
	return append([]string{"-n", systemNamespace, "exec",
		podName, "-c", containerName, "--",
		"ovs-ofctl", "-OOpenFlow13"}, args...)
}

func otherNodeArgs(systemNamespace string, podName string,
	containerName string, args []string) []string {
	return append([]string{"-n", systemNamespace, "exec",
		podName, "-c", containerName, "--"}, args...)
}

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Commands to help diagnose problems with ACI containers",
	Long: `Commands in the debug section may be added, removed, or changed in
different versions of ACI Containers`,
	Example: `acikubectl debug cluster-report -o cluster-report.tar.gz`,
}

var reportCmd = &cobra.Command{
	Use:   "cluster-report",
	Short: "Generate a diagnostic report for your cluster",
	Long: `Generate a report containing diagnostic information related to ACI
containers, including logs, status, and other information.`,
	Run: clusterReport,
}

func init() {
	reportCmd.PersistentFlags().StringP("output", "o", "",
		"Output to the specified file")
	debugCmd.AddCommand(reportCmd)
	RootCmd.AddCommand(debugCmd)
}

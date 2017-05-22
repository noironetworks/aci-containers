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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/spf13/cobra"
)

func execKubectl(args []string, out io.Writer) error {
	baseargs := []string{"--kubeconfig", kubeconfig}
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

	cmds := []reportCmdElem{
		reportCmdElem{
			name: "cluster-report/logs/controller/acc.log",
			args: accLogCmdArgs(),
		},
	}

	kubeClient, err := initClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not initialize kubernetes client:")
		fmt.Fprintln(os.Stderr, err)
		if kubeconfig == "" {
			fmt.Fprintln(os.Stderr,
				"You may need to specify a kubeconfig file with --kubeconfig.")
		}
		return
	}

	nodes, err :=
		kubeClient.CoreV1().Nodes().List(metav1.ListOptions{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not list nodes:", err)
	}

	nodeItems := []reportNodeCmd{
		reportNodeCmd{
			path:     "cluster-report/logs/node-%s/opflex-agent.log",
			cont:     "opflex-agent",
			selector: opflexAgentSelector,
			argFunc:  nodeLogCmdArgs,
		},
		reportNodeCmd{
			path:     "cluster-report/logs/node-%s/aci-containers-host.log",
			cont:     "aci-containers-host",
			selector: hostAgentSelector,
			argFunc:  nodeLogCmdArgs,
		},
		reportNodeCmd{
			path:     "cluster-report/logs/node-%s/aci-containers-openvswitch.log",
			cont:     "aci-containers-openvswitch",
			selector: openvswitchSelector,
			argFunc:  nodeLogCmdArgs,
		},
		reportNodeCmd{
			path:     "cluster-report/cmds/node-%s/gbp-inspect.log",
			cont:     "opflex-agent",
			selector: opflexAgentSelector,
			argFunc:  inspectArgs,
			args:     []string{"-rfpq", "DmtreeRoot"},
		},
		reportNodeCmd{
			path:     "cluster-report/cmds/node-%s/ovs-ofctl-dump-flows-int.log",
			cont:     "aci-containers-openvswitch",
			selector: openvswitchSelector,
			argFunc:  ovsOfCtlArgs,
			args:     []string{"dump-flows", "br-int"},
		},
		reportNodeCmd{
			path:     "cluster-report/cmds/node-%s/ovs-ofctl-dump-flows-access.log",
			cont:     "aci-containers-openvswitch",
			selector: openvswitchSelector,
			argFunc:  ovsOfCtlArgs,
			args:     []string{"dump-flows", "br-access"},
		},
		reportNodeCmd{
			path:     "cluster-report/cmds/node-%s/ovs-vsctl-show.log",
			cont:     "aci-containers-openvswitch",
			selector: openvswitchSelector,
			argFunc:  ovsVsCtlArgs,
			args:     []string{"show"},
		},
		reportNodeCmd{
			path:     "cluster-report/cmds/node-%s/ip-a.log",
			cont:     "aci-containers-openvswitch",
			selector: openvswitchSelector,
			argFunc:  otherNodeArgs,
			args:     []string{"ip", "a"},
		},
		reportNodeCmd{
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
				podName, err = podForNode(node.Name, nodeItem.selector)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					continue
				}
			}

			cmds = append(cmds, reportCmdElem{
				name: fmt.Sprintf(nodeItem.path, node.Name),
				args: nodeItem.argFunc(podName, nodeItem.cont, nodeItem.args),
			})
		}
	}

	outfile, err := os.Create(output)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer outfile.Close()

	gzWriter := gzip.NewWriter(outfile)
	tarWriter := tar.NewWriter(gzWriter)

	now := time.Now()
	hasErrors := false
	for _, cmd := range cmds {
		buffer := new(bytes.Buffer)

		fmt.Fprintln(os.Stderr, "Running command: kubectl", cmd.args)
		err = execKubectl(cmd.args, buffer)
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

func accLogCmdArgs() []string {
	return []string{"-n", "kube-system", "--limit-bytes=10048576",
		"logs", "deployment/aci-containers-controller",
		"-c", "aci-containers-controller"}
}

func accLog(cmd *cobra.Command, args []string) {
	outputCmd(logCmd, accLogCmdArgs())
}

type nodeCmdArgFunc func(string, string, []string) []string

func nodeCmd(cmd *cobra.Command, args []string, selector string,
	containerName string, argFunc nodeCmdArgFunc) {

	node, err := cmd.PersistentFlags().GetString("node")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if node == "" {
		fmt.Fprintln(os.Stderr, "Node not specified (use --node)")
		return
	}

	podName, err := podForNode(node, selector)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	outputCmd(logCmd, argFunc(podName, containerName, args))
}

func nodeLogCmdArgs(podName string, containerName string,
	args []string) []string {

	return []string{"-n", "kube-system", "--limit-bytes=10048576",
		"logs", podName, "-c", containerName}
}

func podForNode(node string, selector string) (string, error) {
	kubeClient, err := initClient()
	if err != nil {
		return "", err
	}

	opts := metav1.ListOptions{
		LabelSelector: selector,
	}
	pods, err :=
		kubeClient.CoreV1().Pods("kube-system").List(opts)
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

const opflexAgentSelector = "network-plugin=aci-containers,name=aci-containers-host"
const hostAgentSelector = "network-plugin=aci-containers,name=aci-containers-host"
const openvswitchSelector = "network-plugin=aci-containers,name=aci-containers-openvswitch"

func opflexAgentLog(cmd *cobra.Command, args []string) {
	nodeCmd(nodeLogCmd, args, opflexAgentSelector,
		"opflex-agent", nodeLogCmdArgs)
}

func hostAgentLog(cmd *cobra.Command, args []string) {
	nodeCmd(nodeLogCmd, args, hostAgentSelector,
		"aci-containers-host", nodeLogCmdArgs)
}

func openvswitchLog(cmd *cobra.Command, args []string) {
	nodeCmd(nodeLogCmd, args, openvswitchSelector,
		"aci-containers-openvswitch", nodeLogCmdArgs)
}

func inspectArgs(podName string, containerName string,
	args []string) []string {
	return append([]string{"-n", "kube-system", "exec",
		podName, "-c", containerName, "--", "gbp_inspect"}, args...)
}

func inspect(cmd *cobra.Command, args []string) {
	nodeCmd(cmdCmd, args, opflexAgentSelector, "opflex-agent", inspectArgs)
}

func ovsVsCtlArgs(podName string, containerName string,
	args []string) []string {
	return append([]string{"-n", "kube-system", "exec",
		podName, "-c", containerName, "--", "ovs-vsctl"}, args...)
}

func ovsVsCtl(cmd *cobra.Command, args []string) {
	nodeCmd(cmdCmd, args, openvswitchSelector,
		"aci-containers-openvswitch", ovsVsCtlArgs)
}

func ovsOfCtlArgs(podName string, containerName string,
	args []string) []string {
	return append([]string{"-n", "kube-system", "exec",
		podName, "-c", containerName, "--",
		"ovs-ofctl", "-OOpenFlow13"}, args...)
}

func ovsOfCtl(cmd *cobra.Command, args []string) {
	nodeCmd(cmdCmd, args, openvswitchSelector,
		"aci-containers-openvswitch", ovsOfCtlArgs)
}

func otherNodeArgs(podName string, containerName string,
	args []string) []string {
	return append([]string{"-n", "kube-system", "exec",
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

var logCmd = &cobra.Command{
	Use:   "logs",
	Short: "Get logs from ACI containers components",
}

var controllerLogCmd = &cobra.Command{
	Use:   "controller",
	Short: "Get logs from an ACI containers controller container",
}

var accControllerLogCmd = &cobra.Command{
	Use:   "acc",
	Short: "Get logs from the ACC container",
	Run:   accLog,
}

var nodeLogCmd = &cobra.Command{
	Use:   "node",
	Short: "Get logs from an ACI containers host container",
}

var opflexAgentNodeLogCmd = &cobra.Command{
	Use:   "opflex-agent",
	Short: "Get logs from the opflex agent container",
	Run:   opflexAgentLog,
}

var hostAgentNodeLogCmd = &cobra.Command{
	Use:   "host-agent",
	Short: "Get logs from the host agent container",
	Run:   hostAgentLog,
}

var openvswitchNodeLogCmd = &cobra.Command{
	Use:   "openvswitch",
	Short: "Get logs from the openvswitch container",
	Run:   openvswitchLog,
}

var cmdCmd = &cobra.Command{
	Use:   "node-cmd",
	Short: "Run a command on an ACI containers host container",
}

var inspectCmd = &cobra.Command{
	Use:     "gbp-inspect",
	Short:   "Run the GBP inspect tool for a node",
	Example: `acikubectl debug cmd -n node1 gbp-inspect -- -rq DmtreeRoot`,
	Run:     inspect,
}

var ovsVsCtlCmd = &cobra.Command{
	Use:     "ovs-vsctl",
	Short:   "Run the ovs-vsctl tool for a node",
	Example: `acikubectl debug cmd -n node1 ovs-vsctl -- show`,
	Run:     ovsVsCtl,
}

var ovsOfCtlCmd = &cobra.Command{
	Use:     "ovs-ofctl",
	Short:   "Run the ovs-ofctl tool for a node",
	Example: `acikubectl debug cmd -n node1 ovs-ofctl -- dump-flows br-int`,
	Run:     ovsOfCtl,
}

func init() {
	logCmd.PersistentFlags().StringP("output", "o", "",
		"Output to the specified file")

	controllerLogCmd.AddCommand(accControllerLogCmd)
	logCmd.AddCommand(controllerLogCmd)

	nodeLogCmd.PersistentFlags().StringP("node", "n", "",
		"Get logs from the specified node")
	nodeLogCmd.AddCommand(opflexAgentNodeLogCmd)
	nodeLogCmd.AddCommand(hostAgentNodeLogCmd)
	nodeLogCmd.AddCommand(openvswitchNodeLogCmd)
	logCmd.AddCommand(nodeLogCmd)

	reportCmd.PersistentFlags().StringP("output", "o", "",
		"Output to the specified file")

	cmdCmd.PersistentFlags().StringP("node", "n", "",
		"Run command on the specified node")
	cmdCmd.AddCommand(inspectCmd)
	cmdCmd.AddCommand(ovsVsCtlCmd)
	cmdCmd.AddCommand(ovsOfCtlCmd)

	debugCmd.AddCommand(logCmd)
	debugCmd.AddCommand(reportCmd)
	debugCmd.AddCommand(cmdCmd)
	RootCmd.AddCommand(debugCmd)
}

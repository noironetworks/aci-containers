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

func clusterReport(cmd *cobra.Command, args []string) {
	output, err := cmd.PersistentFlags().GetString("output")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	cmds := []reportCmdElem{
		reportCmdElem{
			name: "cluster-report/logs/controller/acc.log",
			args: accLogCmdArgs(),
		},
		reportCmdElem{
			name: "cluster-report/logs/controller/aid.log",
			args: aidLogCmdArgs(),
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

	const nodeLog = "cluster-report/logs/node-%s/%s.log"
	nodeLogItems := map[string]string{
		"opflex-agent":               opflexAgentSelector,
		"aci-containers-host":        hostAgentSelector,
		"aci-containers-openvswitch": openvswitchSelector,
	}

	for _, node := range nodes.Items {
		for cont, selector := range nodeLogItems {
			cmdArgs, err := nodeLogCmdArgs(node.Name, selector, cont)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				continue
			}
			cmds = append(cmds, reportCmdElem{
				name: fmt.Sprintf(nodeLog, node.Name, cont),
				args: cmdArgs,
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
	defer gzWriter.Close()

	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	for _, cmd := range cmds {
		buffer := new(bytes.Buffer)

		err = execKubectl(cmd.args, buffer)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}

		tarWriter.WriteHeader(&tar.Header{
			Name: cmd.name,
			Mode: 0644,
			Size: int64(buffer.Len()),
		})
		buffer.WriteTo(tarWriter)
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

func aidLogCmdArgs() []string {
	return []string{"-n", "kube-system", "--limit-bytes=10048576",
		"logs", "deployment/aci-containers-controller",
		"-c", "aci-integration-module"}
}

func accLogCmdArgs() []string {
	return []string{"-n", "kube-system", "--limit-bytes=10048576",
		"logs", "deployment/aci-containers-controller",
		"-c", "aci-containers-controller"}
}

func aidLog(cmd *cobra.Command, args []string) {
	outputCmd(logCmd, aidLogCmdArgs())
}

func accLog(cmd *cobra.Command, args []string) {
	outputCmd(logCmd, accLogCmdArgs())
}

func nodeLog(selector string, containerName string) {
	node, err := nodeLogCmd.PersistentFlags().GetString("node")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if node == "" {
		fmt.Fprintln(os.Stderr, "Node not specified (use --node)")
		return
	}

	args, err := nodeLogCmdArgs(node, selector, containerName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	outputCmd(logCmd, args)
}

func nodeLogCmdArgs(node string, selector string,
	containerName string) ([]string, error) {

	kubeClient, err := initClient()
	if err != nil {
		return nil, err
	}

	opts := metav1.ListOptions{
		LabelSelector: selector,
	}
	pods, err :=
		kubeClient.CoreV1().Pods("kube-system").List(opts)
	if err != nil {
		return nil, err
	}
	for _, pod := range pods.Items {
		if pod.Spec.NodeName == node {
			return []string{"-n", "kube-system",
				"--limit-bytes=10048576",
				"logs", pod.Name, "-c", containerName}, nil
		}
	}
	return nil, errors.New("Could not find pod on node: " + node)
}

const opflexAgentSelector = "network-plugin=aci-containers,name=aci-containers-host"
const hostAgentSelector = "network-plugin=aci-containers,name=aci-containers-host"
const openvswitchSelector = "network-plugin=aci-containers,name=aci-containers-openvswitch"

func opflexAgentLog(cmd *cobra.Command, args []string) {
	nodeLog(opflexAgentSelector, "opflex-agent")
}

func hostAgentLog(cmd *cobra.Command, args []string) {
	nodeLog(hostAgentSelector, "aci-containers-host")
}

func openvswitchLog(cmd *cobra.Command, args []string) {
	nodeLog(openvswitchSelector, "aci-containers-openvswitch")
}

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Commands to help diagnose problems with ACI containers",
	Long: `Commands in the debug section may be added, removed, or changed in
different versions of ACI Containers`,
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

var aidControllerLogCmd = &cobra.Command{
	Use:   "aid",
	Short: "Get logs from the AID container",
	Run:   aidLog,
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

func init() {
	logCmd.PersistentFlags().StringP("output", "o", "",
		"Output to the specified file")

	controllerLogCmd.AddCommand(aidControllerLogCmd)
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

	debugCmd.AddCommand(logCmd)
	debugCmd.AddCommand(reportCmd)
	RootCmd.AddCommand(debugCmd)
}

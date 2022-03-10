// Copyright 2017 Cisco Systems, Inc.
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
	kubecontext "context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/spf13/cobra"
)

func getNodes() (*v1.NodeList, error) {
	kubeClient := initClientPrintError()
	if kubeClient == nil {
		fmt.Fprintln(os.Stderr, "Could not get kubeclient", nil)
		return nil, nil
	}

	nodes, err :=
		kubeClient.CoreV1().Nodes().List(kubecontext.TODO(), metav1.ListOptions{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not list nodes:", err)
	}

	return nodes, err
}

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
	name           string
	args           []string
	skipOutputFile bool
}

type reportNodeCmd struct {
	path     string
	cont     string
	selector string
	args     []string
	argFunc  nodeCmdArgFunc
}

func addFileToTarball(path string, tarWriter *tar.Writer) error {
	file, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Can not open the file", path)
		return err
	}
	defer file.Close()

	if stat, err := file.Stat(); err == nil {
		// now lets create the header as needed for this file within the tarball
		header := new(tar.Header)
		header.Name = "cluster-report/hostfiles.tar"
		header.Size = stat.Size()
		header.Mode = 0644
		header.ModTime = time.Now()
		// write the header to the tarball archive
		if err := tarWriter.WriteHeader(header); err != nil {
			fmt.Fprintf(os.Stderr, "Can not write file %s header to tarball", path)
			return err
		}
		// copy the file data to the tarball
		if _, err := io.Copy(tarWriter, file); err != nil {
			fmt.Fprintf(os.Stderr, "Can not copy file %s to tarball", path)
			return err
		}
	}
	return nil
}

func createTarForClusterReport(tarWriter *tar.Writer) error {
	// Create tar file out for all kubectl cp files
	createTarCmd := exec.Command("tar", "-cvf", "hostfiles.tar", "hostfiles/")
	err := createTarCmd.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error while running command")
		return err
	}

	// write hostfiles.tar file to cluster-report tar
	err = addFileToTarball("hostfiles.tar", tarWriter)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not add files.tar to cluster-report tar")
		return err
	}

	// Delete tar and cluster-report/files dir
	deleteCmds := []string{"rm -rf cluster-report/",
		"rm -rf hostfiles.tar",
		"rm -rf hostfiles",
	}

	for _, cmd := range deleteCmds {
		cmdOp := exec.Command("/bin/sh", "-c", cmd)
		err = cmdOp.Run()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error while running command ", cmd)
			return err
		}
	}

	return nil
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

	ipam_path := "-o=jsonpath={range.items[*]}{@.metadata.name}\n{@.metadata.annotations.opflex\\.cisco\\.com/pod-network-ranges}\n"

	cmds := []reportCmdElem{
		{
			name: "cluster-report/logs/controller/acc.log",
			args: accLogCmdArgs(systemNamespace),
		},
		{
			name: "cluster-report/logs/controller/controller-config.log",
			args: controllerConfigCmdArgs(systemNamespace),
		},
		{
			name: "cluster-report/logs/controller/controller-status.log",
			args: controllerStatusCmdArgs(systemNamespace),
		},
		{
			name: "cluster-report/logs/controller/acc-version.log",
			args: accVersionCmdArgs(systemNamespace),
		},
		{
			name: "cluster-report/logs/operator/acioperator.log",
			args: acioperatorLogCmdArgs(systemNamespace),
		},
		{
			name: "cluster-report/logs/operator/accprovisionoperator.log",
			args: accprovisionoperatorLogCmdArgs(systemNamespace),
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
			name: "cluster-report/status/acioperator_deployment_status.log",
			args: []string{"-n", systemNamespace, "describe", "deployment",
				"aci-containers-operator"},
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
			args: []string{"get", "pods", "--all-namespaces", "--output=wide"},
		},
		{
			name: "cluster-report/status/services_status.log",
			args: []string{"get", "services", "--all-namespaces"},
		},
		{
			name: "cluster-report/status/cluster-info.log",
			args: []string{"cluster-info"},
		},
		{
			name: "cluster-report/status/configmap_controller.log",
			args: []string{"-n", systemNamespace, "describe", "configmap", "aci-containers-config"},
		},
		{
			name: "cluster-report/status/configmap_snatoperator.log",
			args: []string{"-n", systemNamespace, "describe", "configmap", "snat-operator"},
		},
		{
			name: "cluster-report/status/configmap_acioperator.log",
			args: []string{"-n", systemNamespace, "describe", "configmap", "aci-operator-config"},
		},
		{
			name: "cluster-report/status/configmap_accprovisionoperator.log",
			args: []string{"-n", systemNamespace, "describe", "configmap", "acc-provision-config"},
		},
		{
			name: "cluster-report/status/snat_policy.log",
			args: []string{"describe", "snatpolicy"},
		},
		{
			name: "cluster-report/status/snat_localinfo.log",
			args: []string{"-n", systemNamespace, "describe", "snatlocalinfo"},
		},
		{
			name: "cluster-report/status/snat_globalinfo.log",
			args: []string{"-n", systemNamespace, "describe", "snatglobalinfo"},
		},
		{
			name: "cluster-report/status/node_info.log",
			args: []string{"describe", "nodeinfo", "--all-namespaces"},
		},
		{
			name: "cluster-report/status/node_podifs.log",
			args: []string{"describe", "nodepodifs", "--all-namespaces"},
		},
		{
			name: "cluster-report/status/erspan_policy.log",
			args: []string{"describe", "erspanpolicy", "--all-namespaces"},
		},
		{
			name: "cluster-report/status/netflow_policy.log",
			args: []string{"describe", "netflowpolicy", "--all-namespaces"},
		},
		{
			name: "cluster-report/status/qos_policy.log",
			args: []string{"describe", "qospolicy", "--all-namespaces"},
		},
		{
			name: "cluster-report/logs/versions/kubectl_version.log",
			args: []string{"version"},
		},
		{
			name: "cluster-report/status/describe_aci_namespace_status.log",
			args: []string{"describe", "-n", systemNamespace, "all"},
		},
		{
			name: "cluster-report/status/ipam_details_all_nodes.log",
			args: []string{"get", "nodes", ipam_path},
		},
	}

	// Get all nodes of k8s cluster
	nodes, _ := getNodes()

	nodeItems := []reportNodeCmd{
		{
			path:     "cluster-report/logs/node-%s/opflex-agent.log",
			cont:     "opflex-agent",
			selector: opflexAgentSelector,
			argFunc:  nodeLogCmdArgs,
		},
		{
			path:     "cluster-report/logs/node-%s/mcast-daemon.log",
			cont:     "mcast-daemon",
			selector: mcastDaemonSelector,
			argFunc:  nodeLogCmdArgs,
		},
		{
			path:     "cluster-report/logs/node-%s/aci-containers-host.log",
			cont:     "aci-containers-host",
			selector: hostAgentSelector,
			argFunc:  nodeLogCmdArgs,
		},
		{
			path:     "cluster-report/logs/node-%s/host-ipam.log",
			cont:     "aci-containers-host",
			selector: hostAgentSelector,
			argFunc:  hostAgentLogCmdArgs,
			args:     []string{"--", "curl", "-s", "localhost:8090/ipam"},
		},
		{
			path:     "cluster-report/logs/node-%s/host-status.log",
			cont:     "aci-containers-host",
			selector: hostAgentSelector,
			argFunc:  hostAgentLogCmdArgs,
			args:     []string{"--", "curl", "-s", "localhost:8090/status"},
		},
		{
			path:     "cluster-report/logs/node-%s/host-services.log",
			cont:     "aci-containers-host",
			selector: hostAgentSelector,
			argFunc:  hostAgentLogCmdArgs,
			args:     []string{"--", "curl", "-s", "localhost:8090/services"},
		},
		{
			path:     "cluster-report/logs/node-%s/host-config.log",
			cont:     "aci-containers-host",
			selector: hostAgentSelector,
			argFunc:  hostAgentLogCmdArgs,
			args:     []string{"--", "curl", "-s", "localhost:8090/config"},
		},
		{
			path:     "cluster-report/logs/node-%s/host-endpoints.log",
			cont:     "aci-containers-host",
			selector: hostAgentSelector,
			argFunc:  hostAgentLogCmdArgs,
			args:     []string{"--", "curl", "-s", "localhost:8090/endpoints"},
		},
		{
			path:     "cluster-report/logs/node-%s/aci-containers-openvswitch.log",
			cont:     "aci-containers-openvswitch",
			selector: openvswitchSelector,
			argFunc:  nodeLogCmdArgs,
		},
		{
			path:     "cluster-report/cmds/node-%s/agent-version-githash.log",
			cont:     "opflex-agent",
			selector: opflexAgentSelector,
			argFunc:  inspectArgs,
			args:     []string{"-v"},
		},
		{
			path:     "cluster-report/cmds/node-%s/gbp-inspect.log",
			cont:     "opflex-agent",
			selector: opflexAgentSelector,
			argFunc:  inspectArgs,
			args:     []string{"-rfpq", "DmtreeRoot", "-t", "dump"},
		},
		{
			path:     "cluster-report/cmds/node-%s/gbp-unresolved.log",
			cont:     "opflex-agent",
			selector: opflexAgentSelector,
			argFunc:  inspectArgs,
			args:     []string{"-urq", "DmtreeRoot"},
		},
		{
			path:     "cluster-report/cmds/node-%s/ovs-ofctl-show-int.log",
			cont:     "aci-containers-openvswitch",
			selector: openvswitchSelector,
			argFunc:  ovsOfCtlArgs,
			args:     []string{"show", "br-int"},
		},
		{
			path:     "cluster-report/cmds/node-%s/ovs-ofctl-show-access.log",
			cont:     "aci-containers-openvswitch",
			selector: openvswitchSelector,
			argFunc:  ovsOfCtlArgs,
			args:     []string{"show", "br-access"},
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
		{
			path:     "cluster-report/cmds/node-%s/ovs-conf-db.log",
			cont:     "aci-containers-openvswitch",
			selector: openvswitchSelector,
			argFunc:  otherNodeArgs,
			args:     []string{"cat", "/etc/openvswitch/conf.db"},
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
			// Prepare kubectl cp command for opflex-agent-ovs
			tempName := fmt.Sprintf("hostfiles/node-%s/opflex-agent-ovs/", node.Name)
			cmds = append(cmds, reportCmdElem{
				name: tempName,
				args: []string{"cp", systemNamespace + "/" + podName + ":" +
					"/usr/local/var/lib/opflex-agent-ovs", tempName},
				skipOutputFile: true,
			})

			cmds = append(cmds, reportCmdElem{
				name: fmt.Sprintf(nodeItem.path, node.Name),
				args: nodeItem.argFunc(systemNamespace, podName,
					nodeItem.cont, nodeItem.args),
			})

			//Prepare kubectl cp command for aci-conatiners-host
			tempName = fmt.Sprintf("hostfiles/node-%s/aci-containers/k8s-pod-network/", node.Name)
			cmds = append(cmds, reportCmdElem{
				name: tempName,
				args: []string{"cp", systemNamespace + "/" + podName + ":" +
					"/usr/local/var/lib/aci-containers/k8s-pod-network", tempName},
				skipOutputFile: true,
			})
		}
		//Prepare kubectl exec command for aci-conatiners-host version
		tempName := fmt.Sprintf("cluster-report/logs/node-%s/aci-containers-host-version.log", node.Name)
		cmds = append(cmds, reportCmdElem{
			name: tempName,
			args: aciContainerHostVersionCmdArgs(systemNamespace),
		})
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
		//To avoid having double hostfiles
		if !cmd.skipOutputFile {
			tarWriter.WriteHeader(&tar.Header{
				Name:    cmd.name,
				Mode:    0644,
				ModTime: now,
				Size:    int64(buffer.Len()),
			})
			buffer.WriteTo(tarWriter)
		}
	}

	createTarForClusterReport(tarWriter)

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

func accLogCmdArgs(systemNamespace string) []string {
	return []string{"-n", systemNamespace, "logs",
		"deployment/aci-containers-controller",
		"-c", "aci-containers-controller"}
}

func accprovisionoperatorLogCmdArgs(systemNamespace string) []string {
	return []string{"-n", systemNamespace, "logs",
		"deployment/aci-containers-operator",
		"-c", "acc-provision-operator"}
}

func acioperatorLogCmdArgs(systemNamespace string) []string {
	return []string{"-n", systemNamespace, "logs",
		"deployment/aci-containers-operator",
		"-c", "aci-containers-operator"}
}

func accVersionCmdArgs(systemNamespace string) []string {
	return []string{"-n", systemNamespace, "exec", "deployment/aci-containers-controller",
		"-c", "aci-containers-controller", "-i", "--",
		"aci-containers-controller", "--version"}
}

func controllerConfigCmdArgs(systemNamespace string) []string {
	return []string{"-n", systemNamespace, "exec", "deployment/aci-containers-controller",
		"-c", "aci-containers-controller", "--", "curl", "-s", "localhost:8091/config"}
}

func controllerStatusCmdArgs(systemNamespace string) []string {
	return []string{"-n", systemNamespace, "exec", "deployment/aci-containers-controller",
		"-c", "aci-containers-controller", "--", "curl", "-s", "localhost:8091/status"}
}

func aciContainerHostVersionCmdArgs(systemNamespace string) []string {
	return []string{"-n", systemNamespace, "exec", "daemonsets/aci-containers-host",
		"-c", "aci-containers-host", "-i", "--",
		"aci-containers-host-agent", "--version"}
}

func hostAgentLogCmdArgs(systemNamespace string, podName string, containerName string, args []string) []string {
	return append([]string{"-n", systemNamespace, "exec", podName,
		"-c", containerName}, args...)
}

type nodeCmdArgFunc func(string, string, string, []string) []string

func nodeLogCmdArgs(systemNamespace string, podName string,
	containerName string, args []string) []string {

	return []string{"-n", systemNamespace, "logs",
		podName, "-c", containerName}
}

func findSystemNamespace(kubeClient kubernetes.Interface) (string, error) {
	opts := metav1.ListOptions{
		LabelSelector: namespaceSelector,
	}
	namespaces, err :=
		kubeClient.CoreV1().Namespaces().List(kubecontext.TODO(), opts)
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
		kubeClient.CoreV1().Pods(systemNamespace).List(kubecontext.TODO(), opts)
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
const mcastDaemonSelector = "network-plugin=aci-containers,name=aci-containers-host"
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

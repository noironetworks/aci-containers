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
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/noironetworks/aci-containers/pkg/metadata"
)

func updateObjectAnnot(annot string, newValue string, cmd *cobra.Command,
	args []string) {
	kubeClient := initClientPrintError()
	if kubeClient == nil {
		return
	}

	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Error: Object name not specified\n\n")
		cmd.Usage()
		return
	}

	var options metav1.GetOptions
	if strings.HasPrefix(cmd.Use, "namespace") {
		client := kubeClient.CoreV1().Namespaces()
		ns, err := client.Get(args[0], options)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if newValue != "" {
			if ns.Annotations == nil {
				ns.Annotations = make(map[string]string)
			}
			ns.Annotations[annot] = newValue
		} else {
			delete(ns.Annotations, annot)
		}

		_, err = client.Update(ns)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	} else if strings.HasPrefix(cmd.Use, "deployment") {
		namespace, err := cmd.PersistentFlags().GetString("namespace")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}

		client := kubeClient.ExtensionsV1beta1().Deployments(namespace)
		dep, err := client.Get(args[0], options)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if newValue != "" {
			if dep.Annotations == nil {
				dep.Annotations = make(map[string]string)
			}
			dep.Annotations[annot] = newValue
		} else {
			delete(dep.Annotations, annot)
		}

		_, err = client.Update(dep)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	} else if strings.HasPrefix(cmd.Use, "pod") {
		namespace, err := cmd.PersistentFlags().GetString("namespace")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}

		client := kubeClient.CoreV1().Pods(namespace)
		pod, err := client.Get(args[0], options)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if newValue != "" {
			if pod.Annotations == nil {
				pod.Annotations = make(map[string]string)
			}
			pod.Annotations[annot] = newValue
		} else {
			delete(pod.Annotations, annot)
		}

		_, err = client.Update(pod)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	} else {
		fmt.Fprintf(os.Stderr, "Unknown scope for update annotation: \"%s\"\n"+
			"(Allowed values: namespace, deployment, pod)\n",
			cmd.Use)
		return
	}
}

func getObjectAnnot(annot string, format func(string),
	cmd *cobra.Command, args []string) {
	kubeClient := initClientPrintError()
	if kubeClient == nil {
		return
	}

	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Error: Object name not specified\n\n")
		cmd.Usage()
		return
	}

	var annotValue string
	var options metav1.GetOptions

	if strings.HasPrefix(cmd.Use, "namespace") {
		client := kubeClient.CoreV1().Namespaces()
		ns, err := client.Get(args[0], options)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		annotValue = ns.Annotations[annot]
	} else if strings.HasPrefix(cmd.Use, "deployment") {
		namespace, err := cmd.PersistentFlags().GetString("namespace")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}

		client := kubeClient.ExtensionsV1beta1().Deployments(namespace)
		dep, err := client.Get(args[0], options)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		annotValue = dep.Annotations[annot]
	} else if strings.HasPrefix(cmd.Use, "pod") {
		namespace, err := cmd.PersistentFlags().GetString("namespace")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}

		client := kubeClient.CoreV1().Pods(namespace)
		pod, err := client.Get(args[0], options)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		annotValue = pod.Annotations[annot]
	} else {
		fmt.Fprintf(os.Stderr, "Unknown scope for get annotation: \"%s\"\n"+
			"(Allowed values: namespace, deployment, pod)\n",
			cmd.Use)
		return
	}

	format(annotValue)
}

func formatEgAnnot(egAnnot string) {
	if egAnnot == "" {
		fmt.Println("Not set")
		return
	}

	g := &metadata.OpflexGroup{}
	err := json.Unmarshal([]byte(egAnnot), g)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not decode EG annotation: %s: %v",
			egAnnot, err)
	} else {
		fmt.Println("Endpoint Group:")
		if g.Tenant != "" {
			fmt.Println("  Tenant:", g.Tenant)
		} else {
			fmt.Println("  Tenant:", g.PolicySpace)
		}
		if g.AppProfile != "" {
			fmt.Println("  App profile:", g.AppProfile)
			fmt.Println("  Endpoint group:", g.Name)
		} else {
			eg := strings.Split(g.Name, "|")
			if len(eg) == 2 {
				fmt.Println("  App profile:", eg[0])
				fmt.Println("  Endpoint group:", eg[1])
			} else {
				fmt.Println("  Endpoint group:", g.Name)
			}
		}
	}
}

func formatSgAnnot(sgAnnot string) {
	if sgAnnot == "" {
		fmt.Println("Not set")
		return
	}

	g := make([]metadata.OpflexGroup, 0)
	err := json.Unmarshal([]byte(sgAnnot), &g)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not decode SG annotation: %s: %v",
			sgAnnot, err)
	} else {
		for _, group := range g {
			fmt.Println("Security Group:")
			if group.Tenant != "" {
				fmt.Println("  Tenant:", group.Tenant)
			} else {
				fmt.Println("  Tenant:", group.PolicySpace)
			}
			fmt.Println("  Security Group:", group.Name)
		}
	}
}

func formatRaw(annot string) {
	fmt.Println(annot)
}

func getDefaultEg(cmd *cobra.Command, args []string) {
	raw, err := cmd.PersistentFlags().GetBool("raw")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	format := formatEgAnnot
	if raw {
		format = formatRaw
	}
	getObjectAnnot(metadata.EgAnnotation, format, cmd, args)
}

func setDefaultEg(cmd *cobra.Command, args []string) {
	clear, err := cmd.PersistentFlags().GetBool("clear")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	var egAnnot string
	if clear {
		fmt.Println("Clearing default endpoint group")
	} else {
		tenant, err := cmd.PersistentFlags().GetString("tenant")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		appProfile, err := cmd.PersistentFlags().GetString("app-profile")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		egName, err := cmd.PersistentFlags().GetString("endpoint-group")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}

		eg := &metadata.OpflexGroup{
			Tenant:     tenant,
			AppProfile: appProfile,
			Name:       egName,
		}

		raw, err := json.Marshal(eg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}

		egAnnot = string(raw)
		fmt.Println("Setting default endpoint group:")
		formatEgAnnot(egAnnot)
	}

	updateObjectAnnot(metadata.EgAnnotation, egAnnot, cmd, args)
}

func getDefaultSg(cmd *cobra.Command, args []string) {
	raw, err := cmd.PersistentFlags().GetBool("raw")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	format := formatSgAnnot
	if raw {
		format = formatRaw
	}

	getObjectAnnot(metadata.SgAnnotation, format, cmd, args)
}

func setDefaultSg(cmd *cobra.Command, args []string) {
	clear, err := cmd.PersistentFlags().GetBool("clear")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	var sgAnnot string
	if clear {
		fmt.Println("Clearing default security groups")
	} else {
		tenant, err := cmd.PersistentFlags().GetString("tenant")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		sgNames, err := cmd.PersistentFlags().GetStringSlice("security-group")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}

		sg := make([]metadata.OpflexGroup, 0)
		for _, sgName := range sgNames {
			sg = append(sg, metadata.OpflexGroup{
				Tenant: tenant,
				Name:   sgName,
			})
		}

		raw, err := json.Marshal(sg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		sgAnnot = string(raw)
		fmt.Println("Setting default security groups:")
		formatSgAnnot(sgAnnot)
	}

	updateObjectAnnot(metadata.SgAnnotation, sgAnnot, cmd, args)
}

var set = &cobra.Command{
	Use:   "set",
	Short: "Set a value",
}

var get = &cobra.Command{
	Use:   "get",
	Short: "Get a value",
}

var setDefaultEgCmd = &cobra.Command{
	Use:   "default-eg",
	Short: "Set the default endpoint group for an object",
	Long: `Set the default endpoint group for the named scope.  Unless a more
specific rule is present, this will be the endpoint group used for
pods in this scope.`,
	Example: `acikubectl set default-eg namespace -t mytenant -g sample-group
acikubectl set-default-eg deployment -t mytenant -g sample-group`,
}

var getDefaultEgCmd = &cobra.Command{
	Use:   "default-eg",
	Short: "Get the default endpoint group for an object",
	Long: `Get the default endpoint group for the named scope.  Unless a more
specific rule is present, this will be the endpoint group used for
pods in this scope.`,
}

var setDefaultSgCmd = &cobra.Command{
	Use:   "default-sg",
	Short: "Set the default security groups",
	Long: `Set the default security groups for a named scope.  Unless a more
specific rule is present, this will be the base set of security groups
used for pods in this scope.`,
	Example: `acikubectl set default-sg namespace -t mytenant \
    -g sample-group -g sample-group2`,
}

var getDefaultSgCmd = &cobra.Command{
	Use:   "default-sg",
	Short: "Get the default security groups",
	Long: `Get the default security groups for a named scope.  Unless a more
specific rule is present, this will be the base set of security groups
used for pods in this scope.`,
}

func init() {
	scopes := []string{"pod", "namespace", "deployment"}
	for _, scope := range scopes {
		var example string
		var nsstring string
		if scope != "namespace" {
			nsstring = "-n objnamespace "
		}

		// Set default endpoint group commands
		example = fmt.Sprintf("acikubectl set-default-eg %s objname %s"+
			"objnamespace -t mytenant \\\n    -a app-profile -g sample-group",
			scope, nsstring)
		cmd := &cobra.Command{
			Use:   fmt.Sprintf("%s [name]", scope),
			Short: fmt.Sprintf("Set the default endpoint group for a %s", scope),
			Long: fmt.Sprintf("Set the default endpoint groups for this %s.  "+
				"Unless a more specific\nrule is present, this will be the "+
				"default endpoint group used for pods\nin this %s.", scope, scope),
			Example: example,
			Run:     setDefaultEg,
		}

		cmd.PersistentFlags().
			BoolP("clear", "", false,
				fmt.Sprintf("Clear the default value for the %s", scope))
		if scope != "namespace" {
			cmd.PersistentFlags().
				StringP("namespace", "n", "default",
					fmt.Sprintf("The kubernetes namespace for the %s", scope))
		}
		cmd.PersistentFlags().
			StringP("tenant", "t", "kubernetes",
				"The ACI tenant for the endpoint group")
		cmd.PersistentFlags().
			StringP("app-profile", "a", "kubernetes", "The endpoint group app profile")
		cmd.PersistentFlags().
			StringP("endpoint-group", "g", "default", "The endpoint group name")

		setDefaultEgCmd.AddCommand(cmd)

		// Get default endpoint group
		cmd = &cobra.Command{
			Use:   fmt.Sprintf("%s [name]", scope),
			Short: fmt.Sprintf("Get the default endpoint group for a %s", scope),
			Long: fmt.Sprintf("Get the default endpoint groups for this %s.  "+
				"Unless a more specific\nrule is present, this will be the "+
				"default endpoint group used for pods\nin this %s.", scope, scope),
			Run: getDefaultEg,
		}
		if scope != "namespace" {
			cmd.PersistentFlags().
				StringP("namespace", "n", "default",
					fmt.Sprintf("The kubernetes namespace for the %s", scope))
		}
		cmd.PersistentFlags().
			BoolP("raw", "", false,
				fmt.Sprintf("Get the raw annotation value without formatting"))
		getDefaultEgCmd.AddCommand(cmd)

		// Set default security group commands
		example = fmt.Sprintf("acikubectl set-default-sg %s objname %s"+
			"-t mytenant \\\n    -g sample-group -g "+
			"sample-group2", scope, nsstring)
		cmd = &cobra.Command{
			Use:   fmt.Sprintf("%s [name]", scope),
			Short: fmt.Sprintf("Set the default security group for a %s", scope),
			Long: fmt.Sprintf("Set the default security groups for this %s.  "+
				"Unless a more\nspecific rule is present, this will be the "+
				"base set of security groups\nused for pods in this %s.",
				scope, scope),
			Example: example,
			Run:     setDefaultSg,
		}

		cmd.PersistentFlags().
			BoolP("clear", "", false,
				fmt.Sprintf("Clear the default value for the %s", scope))
		if scope != "namespace" {
			cmd.PersistentFlags().
				StringP("namespace", "n", "default",
					fmt.Sprintf("The kubernetes namespace for the %s", scope))
		}
		cmd.PersistentFlags().
			StringP("tenant", "t", "kubernetes",
				"The ACI tenant for the security groups")
		cmd.PersistentFlags().
			StringSliceP("security-group", "g", nil, "A set of security group names")

		setDefaultSgCmd.AddCommand(cmd)

		// Get default security groups
		cmd = &cobra.Command{
			Use:   fmt.Sprintf("%s [name]", scope),
			Short: fmt.Sprintf("Get the default security groups for a %s", scope),
			Long: fmt.Sprintf("Get the default security groups for this %s.  "+
				"Unless a more specific\nrule is present, this will be the "+
				"default endpoint group used for pods\nin this %s.", scope, scope),
			Run: getDefaultSg,
		}
		if scope != "namespace" {
			cmd.PersistentFlags().
				StringP("namespace", "n", "default",
					fmt.Sprintf("The kubernetes namespace for the %s", scope))
		}
		cmd.PersistentFlags().
			BoolP("raw", "", false,
				fmt.Sprintf("Get the raw annotation value without formatting"))
		getDefaultSgCmd.AddCommand(cmd)

	}

	set.AddCommand(setDefaultEgCmd)
	set.AddCommand(setDefaultSgCmd)
	get.AddCommand(getDefaultEgCmd)
	get.AddCommand(getDefaultSgCmd)
	RootCmd.AddCommand(set)
	RootCmd.AddCommand(get)
}

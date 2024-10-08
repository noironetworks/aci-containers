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
	"fmt"
	"os"
	"os/user"
	"path"

	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var kubeconfig string
var context string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "acikubectl",
	Short: "Manage ACI Containers objects and annotations for Kubernetes",
	Long: `This tool provides a simple way to manage Kubernetes objects and
annotations for the ACI Containers Controller.  This offers a simple
way to manage the ACI policy for your containers.`,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports Persistent Flags, which, if defined here,
	// will be global for your application.

	usr, err := user.Current()
	defaultkubeconfig := ""
	if err == nil {
		defaultkubeconfig = path.Join(usr.HomeDir, ".kube", "config")
	}
	envKubeConfig := os.Getenv("KUBECONFIG")
	if envKubeConfig != "" {
		defaultkubeconfig = envKubeConfig
	}

	RootCmd.PersistentFlags().StringVar(&kubeconfig,
		"kubeconfig", defaultkubeconfig,
		"Path to the kubeconfig file to use for CLI requests.")
	RootCmd.PersistentFlags().StringVar(&context,
		"context", "",
		"Kubernetes context to use for CLI requests.")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.AutomaticEnv() // read in environment variables that match
}

func initClient() (kubernetes.Interface, error) {
	var restconfig *restclient.Config
	var err error

	// the context is only useful with a kubeconfig
	if kubeconfig != "" {
		// use kubeconfig file from command line
		restconfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{
				ExplicitPath: kubeconfig,
			},
			&clientcmd.ConfigOverrides{
				CurrentContext: context,
			}).ClientConfig()
		if err != nil {
			return nil, err
		}
	} else {
		// creates the in-cluster config
		restconfig, err = restclient.InClusterConfig()
		if err != nil {
			return nil, err
		}
	}

	// creates the client
	return kubernetes.NewForConfig(restconfig)
}

func initClientPrintError() kubernetes.Interface {
	kubeClient, err := initClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not initialize kubernetes client:")
		fmt.Fprintln(os.Stderr, err)
		if kubeconfig == "" {
			fmt.Fprintln(os.Stderr,
				"You may need to specify a kubeconfig file with --kubeconfig.")
		}
		return nil
	}
	return kubeClient
}

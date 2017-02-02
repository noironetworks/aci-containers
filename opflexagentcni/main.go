// Copyright 2014 CNI authors
// Copyright 2016 Cisco Systems, Inc.
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

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"

	cnimd "github.com/noironetworks/aci-containers/metadata"
)

type K8SArgs struct {
	types.CommonArgs
	K8S_POD_NAME               types.UnmarshallableString
	K8S_POD_NAMESPACE          types.UnmarshallableString
	K8S_POD_INFRA_CONTAINER_ID types.UnmarshallableString
}

func loadConf(args *skel.CmdArgs) (*types.NetConf, *K8SArgs, string, error) {
	n := &types.NetConf{}
	if err := json.Unmarshal(args.StdinData, n); err != nil {
		return nil, nil, "", fmt.Errorf("failed to load netconf: %v", err)
	}

	k8sArgs := &K8SArgs{}
	err := types.LoadArgs(args.Args, k8sArgs)
	if err != nil {
		return nil, nil, "", err
	}

	id := args.ContainerID
	if k8sArgs.K8S_POD_NAMESPACE != "" && k8sArgs.K8S_POD_NAME != "" {
		id = fmt.Sprintf("%s_%s", k8sArgs.K8S_POD_NAMESPACE, k8sArgs.K8S_POD_NAME)
	}

	return n, k8sArgs, id, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	n, k8sArgs, id, err := loadConf(args)
	if err != nil {
		return err
	}

	// run the IPAM plugin and get back the config to apply
	var result *types.Result
	if n.IPAM.Type != "opflex-agent-cni-ipam" {
		result, err = ipam.ExecAdd(n.IPAM.Type, args.StdinData)
		if err != nil {
			return err
		}

		if result.IP4 == nil && result.IP6 == nil {
			return errors.New("IPAM plugin returned missing IP config")
		}
	} else {
		result = &types.Result{}
		result.DNS = n.DNS
	}

	metadata := cnimd.ContainerMetadata{
		Id:            id,
		ContIfaceName: args.IfName,
		NetNS:         args.Netns,
		NetConf:       *result,
		Namespace:     string(k8sArgs.K8S_POD_NAMESPACE),
		Pod:           string(k8sArgs.K8S_POD_NAME),
	}

	eprpc, err := NewClient("127.0.0.1:4242", time.Millisecond*500)
	if err != nil {
		return err
	}

	result, err = eprpc.Register(&metadata)
	if err != nil {
		return err
	}

	return result.Print()
}

func cmdDel(args *skel.CmdArgs) error {
	n, _, id, err := loadConf(args)
	if err != nil {
		return err
	}

	if n.IPAM.Type != "opflex-agent-cni-ipam" {
		if err := ipam.ExecDel(n.IPAM.Type, args.StdinData); err != nil {
			return err
		}
	}

	eprpc, err := NewClient("127.0.0.1:4242", time.Millisecond*500)
	if err != nil {
		return err
	}
	_, err = eprpc.Unregister(id)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.PluginSupports("0.2.0"))
}

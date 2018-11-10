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

package metadata

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
)

type ContainerIfaceIP struct {
	Address net.IPNet `json:"address"`
	Gateway net.IP    `json:"gateway,omitempty"`
}

type ContainerIfaceMd struct {
	HostVethName string             `json:"host-veth-name,omitempty"`
	Name         string             `json:"name"`
	Mac          string             `json:"mac,omitempty"`
	Sandbox      string             `json:"sandbox,omitempty"`
	IPs          []ContainerIfaceIP `json:"ips"`
}

type ContainerId struct {
	Namespace string `json:"namespace,omitempty"`
	Pod       string `json:"pod,omitempty"`
	ContId    string `json:"cont-id,omitempty"`
}

type ContainerMetadata struct {
	Id     ContainerId         `json:"id,omitempty"`
	Ifaces []*ContainerIfaceMd `json:"interfaces,omitempty"`
}

func RecordMetadata(datadir string, network string, data ContainerMetadata) error {
	dir := filepath.Join(datadir, network)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	datafile := filepath.Join(dir, data.Id.ContId)
	datacont, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(datafile, datacont, 0644)
}

func LoadMetadata(datadir string, network string,
	mdMap *map[string]map[string]*ContainerMetadata) error {

	dir := filepath.Join(datadir, network)
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, file := range files {
		metadata, err := GetMetadata(datadir, network, file.Name())
		if err == nil {
			podId := metadata.Id.Namespace + "/" + metadata.Id.Pod
			if _, ok := (*mdMap)[podId]; !ok {
				(*mdMap)[podId] = make(map[string]*ContainerMetadata)
			}
			(*mdMap)[podId][metadata.Id.ContId] = metadata
		}
	}

	return nil
}

func CheckMetadata(datadir string, network string) (int64, error) {

	ipMap := make(map[string]string)
	dir := filepath.Join(datadir, network)
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return 0, err
	}

	for _, file := range files {
		metadata, err := GetMetadata(datadir, network, file.Name())
		if err == nil {
			podId := metadata.Id.Namespace + "/" + metadata.Id.Pod
			for _, ifc := range metadata.Ifaces {
				for _, ip := range ifc.IPs {
					curr, ok := ipMap[ip.Address.String()]
					if ok {
						return 0, fmt.Errorf("pod: %s alreay has IP: %s, clashes with pod: %s", curr, ip.Address.String(), podId)
					}

					ipMap[ip.Address.String()] = podId
				}
			}
		}
	}

	return int64(len(ipMap)), nil
}

func GetMetadata(datadir string, network string, id string) (*ContainerMetadata, error) {
	data := &ContainerMetadata{}

	datafile := filepath.Join(datadir, network, id)
	datacont, err := ioutil.ReadFile(datafile)
	if err != nil {
		return data, err
	}

	err = json.Unmarshal(datacont, data)
	return data, err
}

func ClearMetadata(datadir string, network string, id string) error {
	datafile := filepath.Join(datadir, network, id)
	return os.Remove(datafile)
}

func GetIfaceNames(hostVethName string) (string, string) {
	return fmt.Sprintf("pi-%s", hostVethName),
		fmt.Sprintf("pa-%s", hostVethName)
}

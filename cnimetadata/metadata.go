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

package cnimetadata

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

type ContainerMetadata struct {
	Namespace    string `json:"namespace"`
	Pod          string `json:"pod"`
	Id           string `json:"id"`
	HostVethName string `json:"host-veth-name"`
	NetNS        string `json:"net-ns"`
	MAC          string `json:"mac"`
}

func RecordMetadata(datadir string, network string, data ContainerMetadata) error {
	dir := filepath.Join(datadir, network)
	if err := os.MkdirAll(dir, 0644); err != nil {
		return err
	}
	datafile := filepath.Join(dir, data.Id)
	datacont, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(datafile, datacont, 0644)
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

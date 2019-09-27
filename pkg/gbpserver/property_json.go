/***
Copyright 2019 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gbpserver

import (
	"encoding/json"
	"fmt"
)

func (p *Property) MarshalJSON() ([]byte, error) {
	var s struct {
		Name string      `json:"name,omitempty"`
		Data interface{} `json:"data,omitempty"`
	}

	var rp struct {
		Subject string `json:"subject,omitempty"`
		Ref     string `json:"reference_uri,omitempty"`
	}

	s.Name = p.Name
	switch p.Value.(type) {
	case *Property_StrVal:
		ps := p.Value.(*Property_StrVal)
		s.Data = ps.StrVal
	case *Property_IntVal:
		pi := p.Value.(*Property_IntVal)
		s.Data = pi.IntVal
	case *Property_RefVal:
		pr := p.Value.(*Property_RefVal)
		rp.Subject = pr.RefVal.Subject
		rp.Ref = pr.RefVal.ReferenceUri
		s.Data = rp
	}

	return json.Marshal(s)
}

func (p *Property) UnmarshalJSON(data []byte) error {
	var s struct {
		Name string      `json:"name,omitempty"`
		Data interface{} `json:"data,omitempty"`
	}

	type rp struct {
		Subject string `json:"subject,omitempty"`
		Ref     string `json:"reference_uri,omitempty"`
	}

	var ss struct {
		Name      string `json:"name,omitempty"`
		Reference *rp    `json:"data,omitempty"`
	}

	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	p.Name = s.Name
	switch s.Data.(type) {
	case string:
		ps := s.Data.(string)
		psv := &Property_StrVal{StrVal: ps}
		p.Value = psv
	case float64:
		pi := s.Data.(float64)
		piv := &Property_IntVal{IntVal: int32(pi)}
		p.Value = piv
	default:
		if err := json.Unmarshal(data, &ss); err != nil {
			return err
		}

		if ss.Reference == nil {
			return fmt.Errorf("json Unmarshal error")
		}

		p.Value = &Property_RefVal{
			RefVal: &Reference{
				Subject:      ss.Reference.Subject,
				ReferenceUri: ss.Reference.Ref,
			},
		}
	}

	return nil
}

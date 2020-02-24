// Copyright 2020 Cisco Systems, Inc.
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

package controller

import (
	"encoding/json"
	"fmt"
	aciv1 "github.com/noironetworks/aci-containers/pkg/snatpolicy/apis/aci.snat/v1"
	"io/ioutil"
	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"net"
	"net/http"
)

const (
	tlsCertFile = `/usr/local/etc/aci-snat/user.crt`
	tlsKeyFile  = `/usr/local/etc/aci-snat/user.key`
)

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
)

func (cont *AciController) StartHttpServer() {
	cont.log.Info("Starting SnatPolicies Server")
	mux := http.NewServeMux()
	mux.HandleFunc("/validate", cont.admitCustomResource)
	server := &http.Server{
		Addr:    ":8443",
		Handler: mux,
	}
	go func() {
		if err := server.ListenAndServeTLS(tlsCertFile, tlsKeyFile); err != nil {
			cont.log.Error("Failed to Start SnatPolicy HTTP Server", err)
		}
	}()
}

func (cont *AciController) admitCustomResource(w http.ResponseWriter, r *http.Request) {
	cont.log.Debug("Start watching for SnatPoilcies creation")
	cont.serve(w, r)
}

func admissionResponse(err error) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}

func (cont *AciController) serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		data, err := ioutil.ReadAll(r.Body)
		if err != nil {
			cont.log.Error("Reading request body failed: ", err)
			http.Error(w, "reading request body failed: ", http.StatusBadRequest)
			return
		}
		body = data
	}
	if len(body) == 0 {
		cont.log.Info("Empty body:")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		return
	}
	response, _ := cont.serveRequestBody(body)
	resp, err := json.Marshal(response)
	if err != nil {
		cont.log.Error("Could not encode response: ", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}
	if _, err := w.Write(resp); err != nil {
		cont.log.Error("Could not write response: ", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}

func (cont *AciController) serveRequestBody(body []byte) (*v1beta1.AdmissionReview, error) {
	cont.log.Debug("handling request:", body)
	var reviewResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	deserializer := codecs.UniversalDeserializer()
	var err error
	if _, _, err = deserializer.Decode(body, nil, &ar); err != nil {
		cont.log.Error(err)
		reviewResponse = admissionResponse(err)
	} else {
		reviewResponse = cont.validate(&ar)
	}
	cont.log.Debug("sending response:", reviewResponse)

	response := &v1beta1.AdmissionReview{}
	if reviewResponse != nil {
		response.Response = reviewResponse
		response.Response.UID = ar.Request.UID
	}
	return response, nil
}

func (cont *AciController) validate(adReview *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	req := adReview.Request
	allowed := true
	var reason string
	var err error
	// Validate the CR based on kind
	switch req.Kind.Kind {
	case "SnatPolicy":
		resource := aciv1.SnatPolicy{}
		raw := adReview.Request.Object.Raw
		err = json.Unmarshal(raw, &resource)
		allowed, reason = cont.admitSnatPolicy(&resource)
	}
	if err != nil {
		return admissionResponse(err)
	}
	reviewResponse := v1beta1.AdmissionResponse{}
	reviewResponse.Allowed = allowed
	if allowed == false {
		reviewResponse.Result = &metav1.Status{
			Reason: metav1.StatusReason(fmt.Sprintf("Resource Creation Failed: %v", reason)),
		}
	} else {
		reviewResponse.Result = &metav1.Status{
			Reason: "Success",
		}

	}
	return &reviewResponse
}

func (cont *AciController) admitSnatPolicy(snatPolicy *aciv1.SnatPolicy) (bool, string) {
	return cont.validateSnatIP(snatPolicy)
	// TODO Destination IP Validation
}

func (cont *AciController) validateSnatIP(cr *aciv1.SnatPolicy) (bool, string) {
	if len(cr.Spec.Selector.Labels) > 1 {
		return false, "Invalid incoming snatpolicy can't have more than one label"
	}
	cont.indexMutex.Lock()
	snatPolicyCache := make(map[string]*ContSnatPolicy)
	for k, v := range cont.snatPolicyCache {
		snatPolicyCache[k] = v
	}
	cont.indexMutex.Unlock()
	if len(cont.snatPolicyCache) >= 1 {
		cr_labels := cr.Spec.Selector.Labels
		cr_ns := cr.Spec.Selector.Namespace
		for key, item := range snatPolicyCache {
			if cr.ObjectMeta.Name != key {
				for _, val := range item.SnatIp {
					_, net1, _ := parseIP(val)
					for _, ip := range cr.Spec.SnatIp {
						_, net2, err := parseIP(ip)
						if err != nil {
							return false, "Invalid incoming Snatpolicy"
						}
						if net2.Contains(net1.IP) || net1.Contains(net2.IP) {
							return false, "SnatIP's are conflicting across the policies"
						}
					}
				}
				// check if labels are repeated
				item_labels := item.Selector.Labels
				for key, crLabel := range cr_labels {
					if _, ok := item_labels[key]; ok {
						if crLabel == item_labels[key] {
							return false, "Label already exists"
						}
					}
				}
				// if no labels, diff IP and
				// same namespace- reject
				item_ns := item.Selector.Namespace
				if (len(item_labels) == 0) && (len(cr_labels) == 0) && (cr_ns == item_ns) {
					return false, "Same namespace"
				}
			}
		}
	} else {
		for _, ip := range cr.Spec.SnatIp {
			_, _, err := parseIP(ip)
			if err != nil {
				return false, "Invalid incoming Snatpolicy"
			}
		}
	}
	return true, ""
}

func parseIP(cidr string) (net.IP, *net.IPNet, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		ip_temp := net.ParseIP(cidr)
		if ip_temp != nil && ip_temp.To4() != nil {
			cidr = cidr + "/32"
			ip, ipnet, _ = net.ParseCIDR(cidr)
			return ip, ipnet, nil
		} else if ip_temp != nil && ip_temp.To16() != nil {
			cidr = cidr + "/128"
			ip, ipnet, _ = net.ParseCIDR(cidr)
			return ip, ipnet, nil
		} else {
			return nil, nil, err
		}
	}
	return ip, ipnet, err
}

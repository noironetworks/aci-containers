package cfapi

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"code.cloudfoundry.org/cfhttp"
)

// cf-networking-release doesn't provide API structs and methods in a way that can be easily
// fetched and used in a Go project. So the necessary APIs are being defined here instead of
// using cf-networking-release directly.

type Policy struct {
	Source      Source      `json:"source"`
	Destination Destination `json:"destination"`
}

type Source struct {
	ID string `json:"id"`
}

type Destination struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`
	Ports    Ports  `json:"ports"`
}

type Ports struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type PolicyClient interface {
	GetPolicies(ids ...string) ([]Policy, error)
}

type policyClientImpl struct {
	http.Client
	Url string
}

func (c *policyClientImpl) GetPolicies(ids ...string) ([]Policy, error) {
	var policiesResponse struct {
		Policies []Policy `json:"policies"`
	}
	requestURL := c.Url + "/networking/v0/internal/policies"
	if len(ids) > 0 {
		requestURL += "?id=" + strings.Join(ids, ",")
	}
	resp, err := c.Get(requestURL)
	if err != nil {
		return nil, err
	}
	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(resBody, &policiesResponse)
	if err != nil {
		return nil, err
	}

	resp.Body.Close()
	return policiesResponse.Policies, nil
}

func NewNetPolClient(netPolUrl string, caCertFile string, clientCertFile string,
	clientKeyFile string) (PolicyClient, error) {
	tlsConfig, err := cfhttp.NewTLSConfig(clientCertFile, clientKeyFile, caCertFile)
	if err != nil {
		return nil, err
	}
	t := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			// values taken from http.DefaultTransport
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		// value taken from http.DefaultTransport
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsConfig,
	}
	httpClient := policyClientImpl{http.Client{Transport: t, Timeout: 30 * time.Second}, netPolUrl}
	return &httpClient, nil
}

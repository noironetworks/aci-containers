package controller

import (
	"net"
	"testing"

	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/gorilla/websocket"
	apicapi "github.com/noironetworks/aci-containers/pkg/apicapi"
	"github.com/noironetworks/aci-containers/pkg/ipam"
	tu "github.com/noironetworks/aci-containers/pkg/testutil"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"time"
)

type podTest struct {
	uuid      string
	cont      string
	veth      string
	namespace string
	name      string
	ip        string
	mac       string
	eg        string
	sg        string
	qp        string
}

var podTests = []podTest{
	{
		"730a8e7a-8455-4d46-8e6e-f4fdf0e3a667",
		"cont1",
		"veth1",
		"testns",
		"pod1",
		"10.1.1.1",
		"00:0c:29:92:fe:d0",
		egAnnot,
		sgAnnot,
		qpAnnot,
	},
}

const egAnnot = "{\"tenant\": \"testps\", " +
	"\"app-profile\": \"test\", \"name\": \"test-eg\"}"
const sgAnnot = "[{\"tenant\": \"testps\", \"name\": \"test-sg\"}]"
const qpAnnot = "{\"tenant\": \"testps\", " +
	"\"app-profile\": \"test\", \"name\": \"test-qp\"}"

var vrfEpgDn string = "uni/testps/test/test-eg"

type loginSucc struct {
	cert bool
}

type SocketHandler struct {
	ts         *testServer
	socketConn *websocket.Conn
	err        error
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type syncTest struct {
	desiredState   map[string]apicapi.ApicSlice
	containerState map[string]apicapi.ApicSlice
	existing       apicapi.ApicSlice
	expected       []Request
	desc           string
}

type Request struct {
	method string
	uri    string
	body   apicapi.ApicObject
}

type Recorder struct {
	requests []Request
}

func (h *Recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var reqBody apicapi.ApicObject
	json.NewDecoder(req.Body).Decode(&reqBody)
	fmt.Println(req.Method, req.URL)
	h.requests = append(h.requests, Request{
		method: req.Method,
		uri:    req.URL.RequestURI(),
		body:   reqBody,
	})
}

func (h *loginSucc) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	class := "aaaLogin"
	if h.cert {
		class = "webtokenSession"
	}
	result := map[string]interface{}{
		"imdata": []interface{}{
			map[string]interface{}{
				class: map[string]interface{}{
					"attributes": map[string]interface{}{
						"token": "testtoken",
					},
				},
			},
		},
	}
	json.NewEncoder(w).Encode(result)
}

func (h *SocketHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	c, err := upgrader.Upgrade(w, req, nil)

	if err != nil {
		h.err = err
		return
	}

	go func() {
		defer c.Close()

		for {
			_, _, err := c.ReadMessage()
			if _, k := err.(*websocket.CloseError); k {
				break
			}
		}
	}()

	h.socketConn, h.err = c, err
}

type testServer struct {
	mux    *http.ServeMux
	server *httptest.Server

	sh *SocketHandler
}

func newTestServer() *testServer {
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)

	ts := &testServer{
		mux:    mux,
		server: server,
	}
	ts.sh = &SocketHandler{
		ts: ts,
	}
	return ts
}

func existingState() apicapi.ApicSlice {
	bd := apicapi.NewFvBD("common", "testbd1")
	subnet := apicapi.NewFvSubnet(bd.GetDn(), "10.42.10.1/16")
	subnet2 := apicapi.NewFvSubnet(bd.GetDn(), "10.43.10.1/16")
	bd.AddChild(subnet)
	bd.AddChild(subnet2)

	bd2 := apicapi.NewFvBD("common", "testbd2")
	bd0 := apicapi.NewFvBD("common", "testbd0")

	s := apicapi.ApicSlice{bd0, bd, bd2}

	return s
}

func (server *testServer) testConn(key []byte) (*apicapi.ApicConnection, error) {
	u, _ := url.Parse(server.server.URL)
	apic := fmt.Sprintf("%s:%s", u.Hostname(), u.Port())

	log := logrus.New()
	log.Level = logrus.DebugLevel
	log.Formatter = &logrus.TextFormatter{
		DisableColors: true,
	}
	cert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.server.TLS.Certificates[0].Certificate[0],
	})

	n, err := apicapi.New(log, []string{apic}, "admin", "noir0123", key, cert, "kube",
		60, 5)
	if err != nil {
		return nil, err
	}
	n.ReconnectInterval = 5 * time.Millisecond
	return n, nil
}

func TestEpgAnnotation(t *testing.T) {
	initCont := func() *testAciController {
		cont := testController()
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()

		return cont
	}

	cont := initCont()
	cont.run()
	for _, pt := range podTests {
		actual := true
		namespace := namespace(pt.name, pt.eg, pt.sg)
		nskey := cont.aciNameForKey("ns", namespace.Name)
		if nskey == "" {
			cont.log.Error("Could not retrieve namespace key")
			return
		}

		cont.cachedVRFDns = append(cont.cachedVRFDns, "uni/tn-bashokba/ap-aci-containers-bashokba/epg-aci-containers-system")

		expected := cont.handleEpgAnnotationUpdate(nskey, 11, critical, namespace.Name, pt.eg)
		assert.Equal(t, actual, expected)

		cont.checkIfEpgExistNs(namespace) //Checks for annotation of namespace for invalid epg

		deployment := deployment(pt.namespace, pt.name, pt.eg, pt.sg)
		cont.checkIfEpgExistDep(deployment) //checks for annotation of deployment for invalid epg

		pod := pod(pt.namespace, pt.name, pt.eg, pt.sg)
		cont.checkIfEpgExistPod(pod) //checks for annotation of pod for invalid epg

		cont.stop()
	}
}

func TestFaultDnPost(t *testing.T) {
	initCont := func() *testAciController {
		cont := testController()
		cont.config.NodeServiceIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.1.3")},
		}
		cont.config.PodIpPool = []ipam.IpRange{
			{Start: net.ParseIP("10.1.1.2"), End: net.ParseIP("10.1.255.254")},
		}
		cont.AciController.initIpam()

		return cont
	}

	cont := initCont()
	cont.run()
	for _, pt := range podTests {

		namespace := namespace(pt.name, pt.eg, pt.sg)
		nskey := cont.aciNameForKey("ns", namespace.Name)
		if nskey == "" {
			cont.log.Error("Could not retrieve namespace key")
			return
		}

		aObj := apicapi.NewVmmClusterFaultInfo("comp/prov-kube/ctrlr-[domain]-cont/injcont/info", strconv.Itoa(10))

		aObj.SetAttr("faultDesc", "Namespace annotation failed:Reason being Invalid EPG")
		aObj.SetAttr("faultCode", strconv.Itoa(10))
		aObj.SetAttr("faultSeverity", strconv.Itoa(critical))

		server := newTestServer()
		defer server.server.Close()
		server.mux.Handle("/api/aaaLogin.json", &loginSucc{})
		server.mux.Handle("/sockettesttoken", server.sh)

		rec := &Recorder{}
		server.mux.Handle("/api/mo/uni/tn-common/", rec)
		server.mux.Handle("/api/mo/comp/", rec)

		conn, err := server.testConn(nil)
		assert.Nil(t, err)

		slice := apicapi.ApicSlice{aObj}
		apicapi.PrepareApicSlice(existingState(), "kube", nskey)
		conn.WriteApicObjects(nskey, slice)
		stopCh := make(chan struct{})
		go conn.Run(stopCh)
		tu.WaitFor(t, "sync", 500*time.Millisecond,
			func(last bool) (bool, error) {
				return tu.WaitNotNil(t, last, server.sh.socketConn,
					"socket connection"), nil
			})
		close(stopCh)
	}
	cont.stop()
}

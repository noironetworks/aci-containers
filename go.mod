go 1.16

require (
	github.com/Mellanox/sriovnet v1.0.2
	github.com/Shopify/sarama v1.26.1
	github.com/aws/aws-sdk-go v1.38.49
	github.com/caddyserver/caddy v1.0.3 // indirect
	github.com/cenkalti/rpc2 v0.0.0-20200203073230-5ce2854ce0fd // indirect
	github.com/checkpoint-restore/go-criu/v4 v4.1.0 // indirect
	github.com/containernetworking/cni v0.8.1
	github.com/containernetworking/plugins v0.9.1
	github.com/coreos/bbolt v1.3.3 // indirect
	github.com/coreos/etcd v3.3.15+incompatible
	github.com/davecgh/go-spew v1.1.1
	github.com/go-bindata/go-bindata v3.1.1+incompatible // indirect
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/protobuf v1.5.2
	github.com/google/uuid v1.2.0
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/websocket v1.4.2
	github.com/k8snetworkplumbingwg/network-attachment-definition-client v1.1.0
	github.com/kr/pty v1.1.5 // indirect
	github.com/mattn/goveralls v0.0.8 // indirect
	github.com/miekg/dns v1.1.35 // indirect
	github.com/natefinch/pie v0.0.0-20170715172608-9a0d72014007
	github.com/noironetworks/aci-containers/pkg/ipam v0.0.0-20210416053915-d6dec2cca336
	github.com/openshift/api v0.0.0-20200713203337-b2494ecb17dd
	github.com/openshift/client-go v0.0.0-20200326155132-2a6cd50aedd0
	github.com/ovn-org/libovsdb v0.0.0-20210422150337-f29ae9b43ea5
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.11.0
	github.com/robfig/cron v1.1.0 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.1.3
	github.com/spf13/viper v1.7.0
	github.com/stretchr/testify v1.7.0
	github.com/tatsushid/go-fastping v0.0.0-20160109021039-d7bb493dee3e
	github.com/thecodeteam/goscaleio v0.1.0 // indirect
	github.com/vishvananda/netlink v1.1.1-0.20201029203352-d40f9887b852
	github.com/yl2chen/cidranger v1.0.0
	go.etcd.io/etcd v0.5.0-alpha.5.0.20200910180754-dd1b699fc489 // indirect
	golang.org/x/net v0.0.0-20210520170846-37e1c6afe023
	golang.org/x/time v0.0.0-20210723032227-1f47c861a9ac
	google.golang.org/grpc v1.38.0
	istio.io/istio v0.0.0-20200811212058-b18b33f83db7
	k8s.io/api v0.22.0
	k8s.io/apiextensions-apiserver v0.22.0
	k8s.io/apimachinery v0.22.0
	k8s.io/client-go v0.22.0
	k8s.io/code-generator v0.22.0
	k8s.io/heapster v1.2.0-beta.1 // indirect
	k8s.io/kubectl v0.22.0
	k8s.io/kubelet v0.0.0
	k8s.io/kubernetes v1.22.0
	sigs.k8s.io/controller-runtime v0.6.1
)

replace (
	github.com/noironetworks/aci-containers/pkg/ipam => ./pkg/ipam
	go.etcd.io/bbolt => go.etcd.io/bbolt v1.3.3
	google.golang.org/grpc => google.golang.org/grpc v1.26.0
	gopkg.in/square/go-jose.v2 => gopkg.in/square/go-jose.v2 v2.2.2
	k8s.io/api => k8s.io/api v0.22.0
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.22.0
	k8s.io/apimachinery => k8s.io/apimachinery v0.22.0
	k8s.io/apiserver => k8s.io/apiserver v0.22.0
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.22.0
	k8s.io/client-go => k8s.io/client-go v0.22.0
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.22.0
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.22.0
	k8s.io/code-generator => k8s.io/code-generator v0.22.0
	k8s.io/component-base => k8s.io/component-base v0.22.0
	k8s.io/component-helpers => k8s.io/component-helpers v0.22.0
	k8s.io/controller-manager => k8s.io/controller-manager v0.22.0
	k8s.io/cri-api => k8s.io/cri-api v0.22.0
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.22.0
	k8s.io/heapster => k8s.io/heapster v1.2.0-beta.1
	k8s.io/klog => k8s.io/klog v1.0.0
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.22.0
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.22.0
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.22.0
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.22.0
	k8s.io/kubectl => k8s.io/kubectl v0.22.0
	k8s.io/kubelet => k8s.io/kubelet v0.22.0
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.22.0
	k8s.io/metrics => k8s.io/metrics v0.22.0
	k8s.io/mount-utils => k8s.io/mount-utils v0.22.0
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.22.0
	k8s.io/repo-infra => k8s.io/repo-infra v0.0.1-alpha.1
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.22.0
	k8s.io/system-validators => k8s.io/system-validators v1.0.4
	k8s.io/utils => k8s.io/utils v0.0.0-20191114184206-e782cd3c129f
	modernc.org/cc => modernc.org/cc v1.0.0
	modernc.org/golex => modernc.org/golex v1.0.0
	modernc.org/mathutil => modernc.org/mathutil v1.0.0
	modernc.org/strutil => modernc.org/strutil v1.0.0
	modernc.org/xc => modernc.org/xc v1.0.0
	mvdan.cc/interfacer => mvdan.cc/interfacer v0.0.0-20180901003855-c20040233aed
	mvdan.cc/lint => mvdan.cc/lint v0.0.0-20170908181259-adc824a0674b
	mvdan.cc/unparam => mvdan.cc/unparam v0.0.0-20190209190245-fbb59629db34
	rsc.io/goversion => rsc.io/goversion v1.0.0
	sigs.k8s.io/kustomize => sigs.k8s.io/kustomize v2.0.3+incompatible
	sigs.k8s.io/structured-merge-diff => sigs.k8s.io/structured-merge-diff v1.0.1-0.20191108220359-b1b620dd3f06
	sigs.k8s.io/yaml => sigs.k8s.io/yaml v1.1.0
	sourcegraph.com/sqs/pbtypes => sourcegraph.com/sqs/pbtypes v0.0.0-20180604144634-d3ebe8f20ae4
	vbom.ml/util => vbom.ml/util v0.0.0-20160121211510-db5cfe13f5cc
)

module github.com/noironetworks/aci-containers

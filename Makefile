
BASE=github.com/noironetworks/aci-containers
METADATA_SRC=$(wildcard pkg/metadata/*.go)
IPAM_SRC=$(wildcard pkg/ipam/*.go)
INDEX_SRC=$(wildcard pkg/index/*.go)
APICAPI_SRC=$(wildcard pkg/apicapi/*.go)
EPRPCCLIENT_SRC=$(wildcard pkg/eprpcclient/*.go)
HOSTAGENT_SRC=$(wildcard cmd/hostagent/*.go pkg/hostagent/*.go)
AGENTCNI_SRC=$(wildcard cmd/opflexagentcni/*.go)
CONTROLLER_SRC=$(wildcard cmd/controller/*.go pkg/controller/*.go)
ACIKUBECTL_SRC=$(wildcard cmd/acikubectl/*.go cmd/acikubectl/cmd/*.go)
OVSRESYNC_SRC=$(wildcard cmd/ovsresync/*.go)
SIMPLESERVICE_SRC=$(wildcard cmd/simpleservice/*.go)

HOSTAGENT_DEPS=${METADATA_SRC} ${IPAM_SRC} ${HOSTAGENT_SRC}
AGENTCNI_DEPS=${METADATA_SRC} ${EPRPCCLIENT_SRC} ${AGENTCNI_SRC}
CONTROLLER_DEPS= \
	${METADATA_SRC} ${IPAM_SRC} ${INDEX_SRC} \
	${APICAPI_SRC} ${CONTROLLER_SRC}
ACIKUBECTL_DEPS=${METADATA_SRC} ${ACIKUBECTL_SRC}
OVSRESYNC_DEPS=${METADATA_SRC} ${OVSRESYNC_SRC}
SIMPLESERVICE_DEPS=${SIMPLESERVICE_SRC}

BUILD_CMD ?= go build -v
TEST_CMD ?= go test -cover
TEST_ARGS ?=
INSTALL_CMD ?= go install -v
STATIC_BUILD_CMD ?= CGO_ENABLED=0 GOOS=linux ${BUILD_CMD} \
	-ldflags="-s -w" -a -installsuffix cgo
DOCKER_BUILD_CMD ?= docker build
VENDOR_BUILD_CMD ?= glide install -strip-vendor

.PHONY: clean goinstall check all

all: vendor dist/aci-containers-host-agent dist/opflex-agent-cni \
	dist/aci-containers-controller dist/acikubectl dist/ovsresync
all-static: vendor dist-static/aci-containers-host-agent \
	dist-static/opflex-agent-cni dist-static/aci-containers-controller \
	dist-static/ovsresync

vendor-rebuild:
	${VENDOR_BUILD_CMD}
vendor:
	${VENDOR_BUILD_CMD}

clean-dist:
	rm -rf dist
clean-vendor:
	rm -rf vendor
clean: clean-dist clean-vendor

goinstall:
	${INSTALL_CMD} ${BASE}/cmd/opflexagentcni
	${INSTALL_CMD} ${BASE}/cmd/controller
	${INSTALL_CMD} ${BASE}/cmd/hostagent
	${INSTALL_CMD} ${BASE}/cmd/acikubectl

dist/opflex-agent-cni: ${AGENTCNI_DEPS}
	${BUILD_CMD} -o $@ ${BASE}/cmd/opflexagentcni
dist-static/opflex-agent-cni: ${AGENTCNI_DEPS}
	${STATIC_BUILD_CMD} -o $@ ${BASE}/cmd/opflexagentcni

dist/aci-containers-host-agent: ${HOSTAGENT_DEPS}
	${BUILD_CMD} -o $@ ${BASE}/cmd/hostagent
dist-static/aci-containers-host-agent: ${HOSTAGENT_DEPS}
	${STATIC_BUILD_CMD} -o $@ ${BASE}/cmd/hostagent

dist/aci-containers-controller: ${CONTROLLER_DEPS}
	${BUILD_CMD} -o $@ ${BASE}/cmd/controller
dist-static/aci-containers-controller: ${CONTROLLER_DEPS}
	${STATIC_BUILD_CMD} -o $@ ${BASE}/cmd/controller

dist/acikubectl: ${ACIKUBECTL_DEPS}
	${BUILD_CMD} -o $@ ${BASE}/cmd/acikubectl
dist-static/acikubectl: ${ACIKUBECTL_DEPS}
	${STATIC_BUILD_CMD} -o $@ ${BASE}/cmd/acikubectl

dist/ovsresync: ${OVSRESYNC_DEPS}
	${BUILD_CMD} -o $@ ${BASE}/cmd/ovsresync
dist-static/ovsresync: ${OVSRESYNC_DEPS}
	${STATIC_BUILD_CMD} -o $@ ${BASE}/cmd/ovsresync

dist/simpleservice: ${SIMPLESERVICE_DEPS}
	${BUILD_CMD} -o $@ ${BASE}/cmd/simpleservice
dist-static/simpleservice: ${SIMPLESERVICE_DEPS}
	${STATIC_BUILD_CMD} -o $@ ${BASE}/cmd/simpleservice

container-host: dist-static/aci-containers-host-agent dist-static/opflex-agent-cni
	${DOCKER_BUILD_CMD} -t noiro/aci-containers-host -f ./docker/Dockerfile-host .
container-controller: dist-static/aci-containers-controller
	${DOCKER_BUILD_CMD} -t noiro/aci-containers-controller -f ./docker/Dockerfile-controller .
container-opflex-build-base:
	${DOCKER_BUILD_CMD} -t noiro/opflex-build-base -f ./docker/Dockerfile-opflex-build-base docker
container-openvswitch: dist-static/ovsresync
	${DOCKER_BUILD_CMD} -t noiro/openvswitch -f ./docker/Dockerfile-openvswitch .
container-simpleservice: dist-static/simpleservice
	${DOCKER_BUILD_CMD} -t noiro/simpleservice -f ./docker/Dockerfile-simpleservice .

check: check-ipam check-index check-apicapi check-controller check-hostagent
check-ipam:
	${TEST_CMD} ${BASE}/pkg/ipam ${TEST_ARGS}
check-index:
	${TEST_CMD} ${BASE}/pkg/index ${TEST_ARGS}
check-apicapi:
	${TEST_CMD} ${BASE}/pkg/apicapi ${TEST_ARGS}
check-hostagent:
	${TEST_CMD} ${BASE}/pkg/hostagent ${TEST_ARGS}
check-controller:
	${TEST_CMD} ${BASE}/pkg/controller ${TEST_ARGS}

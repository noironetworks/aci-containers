
BASE=github.com/noironetworks/aci-containers
METADATA_SRC=$(wildcard pkg/metadata/*.go)
IPAM_SRC=$(wildcard pkg/ipam/*.go)
INDEX_SRC=$(wildcard pkg/index/*.go)
APICAPI_SRC=$(wildcard pkg/apicapi/*.go)
EPRPCCLIENT_SRC=$(wildcard pkg/eprpcclient/*.go)
HOSTAGENT_SRC=$(wildcard cmd/hostagent/*.go pkg/hostagent/*.go)
AGENTCNI_SRC=$(wildcard cmd/opflexagentcni/*.go)
CONTROLLER_SRC=$(wildcard cmd/controller/*.go pkg/controller/*.go)
GBPSERVER_SRC=$(wildcard cmd/gbpserver/*.go pkg/apiserver/*.go)
ACIKUBECTL_SRC=$(wildcard cmd/acikubectl/*.go cmd/acikubectl/cmd/*.go)
OVSRESYNC_SRC=$(wildcard cmd/ovsresync/*.go)
SIMPLESERVICE_SRC=$(wildcard cmd/simpleservice/*.go)
CFAPI_SRC=$(wildcard pkg/cfapi/*.go)
KEYVALUESVC_SRC=$(wildcard pkg/keyvalueservice/*.go)
CF_COMMON_SRC=$(wildcard pkg/cf_common/*.go)
UTIL_SRC=$(wildcard pkg/util/*.go)
DEBIAN_FILES=$(wildcard debian/*)
GOPKG_FILES=$(wildcard Gopkg.*)
GOBUILD=noirolabs/gobuild1.14
UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
    DOCKER_EXT = -dev
else
    DOCKER_EXT =
endif

HOSTAGENT_DEPS=${METADATA_SRC} ${IPAM_SRC} ${HOSTAGENT_SRC} \
	${CF_ETCD_SRC} ${CF_COMMON_SRC} ${KEYVALUESVC_SRC}
AGENTCNI_DEPS=${METADATA_SRC} ${EPRPCCLIENT_SRC} ${AGENTCNI_SRC}
CONTROLLER_DEPS= \
	${METADATA_SRC} ${IPAM_SRC} ${INDEX_SRC} \
	${APICAPI_SRC} ${CONTROLLER_SRC} \
	${CFAPI_SRC} ${CF_COMMON_SRC} ${KEYVALUESVC_SRC}
ACIKUBECTL_DEPS=${METADATA_SRC} ${ACIKUBECTL_SRC}
OVSRESYNC_DEPS=${METADATA_SRC} ${OVSRESYNC_SRC}
SIMPLESERVICE_DEPS=${SIMPLESERVICE_SRC}
DIST_FILE=aci-containers.tgz

DOCKER_HUB_ID ?= noiro
DOCKER_TAG ?=
BUILD_CMD ?= go build -v
TEST_CMD ?= go test -cover
TEST_ARGS ?=
INSTALL_CMD ?= go install -v
GIT_COMMIT=$(shell scripts/getGitCommit.sh)
PKG_NAME_CONTROLLER=github.com/noironetworks/aci-containers/pkg/controller
PKG_NAME_HOSTAGENT=github.com/noironetworks/aci-containers/pkg/hostagent
PKG_NAME_ACI_CONTAINERS_OPERATOR=github.com/noironetworks/aci-containers/pkg/acicontainersoperator
STATIC_BUILD_CMD ?= CGO_ENABLED=0 GOOS=linux ${BUILD_CMD} \
        -ldflags="\
        -X ${PKG_NAME_CONTROLLER}.buildTime=$(shell date -u +%m-%d-%Y.%H:%M:%S.UTC) \
        -X ${PKG_NAME_CONTROLLER}.gitCommit=${GIT_COMMIT} \
        -X ${PKG_NAME_HOSTAGENT}.buildTime=$(shell date -u +%m-%d-%Y.%H:%M:%S.UTC) \
        -X ${PKG_NAME_HOSTAGENT}.gitCommit=${GIT_COMMIT} \
        -X ${PKG_NAME_ACI_CONTAINERS_OPERATOR}.buildTime=$(shell date -u +%m-%d-%Y.%H:%M:%S.UTC) \
        -X ${PKG_NAME_ACI_CONTAINERS_OPERATOR}.gitCommit=${GIT_COMMIT} \
         -s -w" -a -installsuffix cgo
DOCKER_BUILD_CMD ?= docker build

.PHONY: clean goinstall check all

all: dist/aci-containers-host-agent dist/opflex-agent-cni \
	dist/aci-containers-controller dist/acikubectl dist/ovsresync \
    dist/gbpserver \
    dist/aci-containers-operator
all-static: dist-static/aci-containers-host-agent \
	dist-static/opflex-agent-cni dist-static/aci-containers-controller \
	dist-static/ovsresync dist-static/gbpserver \
    dist-static/aci-containers-operator

go-targets: nodep-opflex-agent-cni nodep-aci-containers-host-agent nodep-aci-containers-controller gbpserver
go-build:
	docker run --rm -m 16g -v ${PWD}:/go/src/github.com/noironetworks/aci-containers -w /go/src/github.com/noironetworks/aci-containers --network=host -it ${GOBUILD} make go-targets

go-gbp-build:
	docker run --rm -m 16g -v ${PWD}:/go/src/github.com/noironetworks/aci-containers -w /go/src/github.com/noironetworks/aci-containers --network=host -it ${GOBUILD} make go-gbp-target
go-gbp-target: gbpserver

clean-dist-static:
	rm -rf dist-static/*
clean-dist:
	rm -rf dist
clean-vendor:
	rm -rf vendor
clean: clean-dist clean-vendor

PACKAGE = aci-containers
VERSION_BASE ?= 1.9.0
VERSION_SUFFIX ?=
VERSION = ${VERSION_BASE}${VERSION_SUFFIX}
BUILD_NUMBER ?= 0
PACKAGE_DIR = ${PACKAGE}-${VERSION}
GOSRC_PATH = ${PACKAGE_DIR}/src/github.com/noironetworks/aci-containers

dist: ${METADATA_SRC} \
	${IPAM_SRC} \
	${INDEX_SRC} \
	${APICAPI_SRC} \
	${EPRPCCLIENT_SRC} \
	${HOSTAGENT_SRC} \
	${AGENTCNI_SRC} \
	${CONTROLLER_SRC} \
	${ACIKUBECTL_SRC} \
	${OVSRESYNC_SRC} \
	${SIMPLESERVICE} \
	${CF_COMMON_SRC} \
        ${UTIL_SRC} \
	${CFAPI_SRC} \
	${KEYVALUESVC_SRC} \
	${DEBIAN_FILES} ${GOPKG_FILES} Makefile
	- rm -rf ${PACKAGE_DIR}
	mkdir -p ${GOSRC_PATH}
	cp --parents -r $^ ${GOSRC_PATH}/
	mv ${GOSRC_PATH}/debian ${PACKAGE_DIR}/
	sed -e "s/@PACKAGE_VERSION@/${VERSION}/" \
		-e "s/@BUILD_NUMBER@/${BUILD_NUMBER}/" \
		${PACKAGE_DIR}/debian/changelog.in \
		> ${PACKAGE_DIR}/debian/changelog
	tar cvzf ${DIST_FILE} ${PACKAGE_DIR}
	rm -rf ${PACKAGE_DIR}

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
dist-static/gbpserver:
	${STATIC_BUILD_CMD} -o $@ ${BASE}/cmd/gbpserver

dist/gbpserver:
	${BUILD_CMD} -o $@ ${BASE}/cmd/gbpserver
gbpserver:
	${STATIC_BUILD_CMD} -o dist-static/gbpserver ${BASE}/cmd/gbpserver
nodep-aci-containers-controller:
	${STATIC_BUILD_CMD} -o dist-static/aci-containers-controller ${BASE}/cmd/controller
nodep-aci-containers-host-agent:
	${STATIC_BUILD_CMD} -o dist-static/aci-containers-host-agent ${BASE}/cmd/hostagent
nodep-opflex-agent-cni:
	${STATIC_BUILD_CMD} -o dist-static/opflex-agent-cni ${BASE}/cmd/opflexagentcni

dist/acikubectl: ${ACIKUBECTL_DEPS}
	${BUILD_CMD} -o $@ ${BASE}/cmd/acikubectl
dist-static/acikubectl: ${ACIKUBECTL_DEPS}
	${STATIC_BUILD_CMD} -o $@ ${BASE}/cmd/acikubectl

dist/aci-containers-operator:
	${BUILD_CMD} -o $@ ${BASE}/cmd/acicontainersoperator
dist-static/aci-containers-operator:
	${STATIC_BUILD_CMD} -o $@ ${BASE}/cmd/acicontainersoperator

dist/ovsresync: ${OVSRESYNC_DEPS}
	${BUILD_CMD} -o $@ ${BASE}/cmd/ovsresync
dist-static/ovsresync: ${OVSRESYNC_DEPS}
	${STATIC_BUILD_CMD} -o $@ ${BASE}/cmd/ovsresync

dist/simpleservice: ${SIMPLESERVICE_DEPS}
	${BUILD_CMD} -o $@ ${BASE}/cmd/simpleservice
dist-static/simpleservice: ${SIMPLESERVICE_DEPS}
	${STATIC_BUILD_CMD} -o $@ ${BASE}/cmd/simpleservice

container-gbpserver: dist-static/gbpserver 
	${DOCKER_BUILD_CMD} -t ${DOCKER_HUB_ID}/gbp-server${DOCKER_TAG} -f ./docker/Dockerfile-gbpserver .
container-host: dist-static/aci-containers-host-agent dist-static/opflex-agent-cni
	${DOCKER_BUILD_CMD} -t ${DOCKER_HUB_ID}/aci-containers-host${DOCKER_TAG} -f ./docker/Dockerfile-host${DOCKER_EXT} .
container-controller: dist-static/aci-containers-controller
	${DOCKER_BUILD_CMD} -t ${DOCKER_HUB_ID}/aci-containers-controller${DOCKER_TAG} -f ./docker/Dockerfile-controller${DOCKER_EXT} .
container-opflex-build-base:
	${DOCKER_BUILD_CMD} -t ${DOCKER_HUB_ID}/opflex-build-base${DOCKER_TAG} -f ./docker/Dockerfile-opflex-build-base docker
container-openvswitch: dist-static/ovsresync
	${DOCKER_BUILD_CMD} -t ${DOCKER_HUB_ID}/openvswitch${DOCKER_TAG} -f ./docker/Dockerfile-openvswitch .
container-cnideploy:
	${DOCKER_BUILD_CMD} -t ${DOCKER_HUB_ID}/cnideploy${DOCKER_TAG} -f ./docker/Dockerfile-cnideploy docker
container-simpleservice: dist-static/simpleservice
	${DOCKER_BUILD_CMD} -t ${DOCKER_HUB_ID}/simpleservice${DOCKER_TAG} -f ./docker/Dockerfile-simpleservice .
container-operator: dist-static/aci-containers-operator
	${DOCKER_BUILD_CMD} -t ${DOCKER_HUB_ID}/aci-containers-operator${DOCKER_TAG} -f ./docker/Dockerfile-operator .

check: check-ipam check-index check-apicapi check-controller check-hostagent check-keyvalueservice check-gbpserver
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
check-gbpserver:
	${TEST_CMD} ${BASE}/pkg/gbpserver/... ${TEST_ARGS}
check-keyvalueservice:
	${TEST_CMD} ${BASE}/pkg/keyvalueservice ${TEST_ARGS}
gometalintercheck:
	@bash ./golang_checks.sh

DEB_PKG_DIR=build-deb-pkg
dsc: dist
	- rm -rf ${DEB_PKG_DIR}
	mkdir -p ${DEB_PKG_DIR}
	cp ${DIST_FILE} ${DEB_PKG_DIR}/
	tar -C $(DEB_PKG_DIR)/ -xf $(DEB_PKG_DIR)/$(DIST_FILE)
	mv $(DEB_PKG_DIR)/$(DIST_FILE) $(DEB_PKG_DIR)/$(PACKAGE)_$(VERSION).orig.tar.gz
	cd $(DEB_PKG_DIR)/$(PACKAGE)-$(VERSION)/; \
		dpkg-buildpackage -d -us -uc -rfakeroot -S

deb: dist
	- rm -rf ${DEB_PKG_DIR}
	mkdir -p ${DEB_PKG_DIR}
	cp ${DIST_FILE} ${DEB_PKG_DIR}/
	tar -C $(DEB_PKG_DIR)/ -xf $(DEB_PKG_DIR)/$(DIST_FILE)
	mv $(DEB_PKG_DIR)/$(DIST_FILE) $(DEB_PKG_DIR)/$(PACKAGE)_$(VERSION).orig.tar.gz
	cd $(DEB_PKG_DIR)/$(PACKAGE)-$(VERSION)/; \
		dpkg-buildpackage -us -uc -rfakeroot -b
	cp $(DEB_PKG_DIR)/*.deb .
	rm -rf $(DEB_PKG_DIR)

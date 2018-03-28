
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
CFAPI_SRC=$(wildcard pkg/cfapi/*.go)
CF_ETCD_SRC=$(wildcard pkg/cf_etcd/*.go)
CF_ETCD_FAKES_SRC=$(wildcard pkg/cf_etcd_fakes/*.go)
DEBIAN_FILES=$(wildcard debian/*)
GOPKG_FILES=$(wildcard Gopkg.*)

HOSTAGENT_DEPS=${METADATA_SRC} ${IPAM_SRC} ${HOSTAGENT_SRC} \
	${CF_ETCD_SRC} vendor
AGENTCNI_DEPS=${METADATA_SRC} ${EPRPCCLIENT_SRC} ${AGENTCNI_SRC} vendor
CONTROLLER_DEPS= \
	${METADATA_SRC} ${IPAM_SRC} ${INDEX_SRC} \
	${APICAPI_SRC} ${CONTROLLER_SRC} ${CF_ETCD_SRC} \
	${CFAPI_SRC} vendor
ACIKUBECTL_DEPS=${METADATA_SRC} ${ACIKUBECTL_SRC} vendor
OVSRESYNC_DEPS=${METADATA_SRC} ${OVSRESYNC_SRC} vendor
SIMPLESERVICE_DEPS=${SIMPLESERVICE_SRC} vendor
DIST_FILE=aci-containers.tgz

BUILD_CMD ?= go build -v
TEST_CMD ?= go test -cover
TEST_ARGS ?=
INSTALL_CMD ?= go install -v
STATIC_BUILD_CMD ?= CGO_ENABLED=0 GOOS=linux ${BUILD_CMD} \
	-ldflags="-s -w" -a -installsuffix cgo
DOCKER_BUILD_CMD ?= docker build
VENDOR_BUILD_CMD ?= dep ensure -v

.PHONY: clean goinstall check all

all: vendor dist/aci-containers-host-agent dist/opflex-agent-cni \
	dist/aci-containers-controller dist/acikubectl dist/ovsresync
all-static: vendor dist-static/aci-containers-host-agent \
	dist-static/opflex-agent-cni dist-static/aci-containers-controller \
	dist-static/ovsresync

vendor-rebuild: Gopkg.lock Gopkg.toml
	${VENDOR_BUILD_CMD}
vendor: Gopkg.lock Gopkg.toml
	${VENDOR_BUILD_CMD}

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
	${CF_ETCD_SRC} \
	${CF_ETCD_FAKES_SRC} \
	${CFAPI_SRC} \
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
container-cnideploy:
	${DOCKER_BUILD_CMD} -t noiro/cnideploy -f ./docker/Dockerfile-cnideploy docker
container-simpleservice: dist-static/simpleservice
	${DOCKER_BUILD_CMD} -t noiro/simpleservice -f ./docker/Dockerfile-simpleservice .

check: check-ipam check-index check-apicapi check-controller check-hostagent check-cf_etcd
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
check-cf_etcd:
	${TEST_CMD} ${BASE}/pkg/cf_etcd ${TEST_ARGS}

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


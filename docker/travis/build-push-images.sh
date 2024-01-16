#!/bin/bash
set -x

git show --summary

DATE_TAG=$(date +"%m%d%y")
RELEASE_TAG_WITH_UPSTREAM_ID=${RELEASE_TAG}.${UPSTREAM_ID}
RELEASE_TAG_WITH_UPSTREAM_ID_DATE_TRAVIS_BUILD_NUMBER=${RELEASE_TAG_WITH_UPSTREAM_ID}.${DATE_TAG}.${TRAVIS_BUILD_NUMBER}
IMAGE_TAG=${RELEASE_TAG_WITH_UPSTREAM_ID_DATE_TRAVIS_BUILD_NUMBER}
IMAGE_TAG_DEV=${RELEASE_TAG}.dev
QUAY_REGISTRY=quay.io/noirolabs
DOCKER_REGISTRY=docker.io/noiro

if [[ "${TRAVIS_TAG}" != "${EXPECTED_TAG_PREFIX}"* ]] ; then
    echo "The applied git tag " ${TRAVIS_TAG} " did not match the expected tag prefix " ${EXPECTED_TAG_PREFIX} ". Skipping building images."
    exit 1
fi

docker login -u=$QUAY_SUMIT_NOIROLABS_ROBO_USER -p=$QUAY_SUMIT_NOIROLABS_ROBO_PSWD quay.io
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /tmp
curl -sSfL https://raw.githubusercontent.com/docker/sbom-cli-plugin/main/install.sh | sh -s --

docker/copy_iptables.sh ${QUAY_REGISTRY}/opflex-build-base:${RELEASE_TAG_WITH_UPSTREAM_ID} dist-static

make -C . all-static

docker/travis/build-openvswitch-travis.sh ${QUAY_REGISTRY} ${IMAGE_TAG}
docker images
docker build -t ${QUAY_REGISTRY}/cnideploy:${IMAGE_TAG} --file=docker/travis/Dockerfile-cnideploy .
docker images
docker build -t ${QUAY_REGISTRY}/aci-containers-controller:${IMAGE_TAG} --file=docker/travis/Dockerfile-controller .
docker images
docker build -t ${QUAY_REGISTRY}/aci-containers-host:${IMAGE_TAG} --file=docker/travis/Dockerfile-host .
docker images
docker build -t ${QUAY_REGISTRY}/aci-containers-operator:${IMAGE_TAG} --file=docker/travis/Dockerfile-operator .
docker images
docker build -t ${QUAY_REGISTRY}/aci-containers-webhook:${IMAGE_TAG} --file=docker/travis/Dockerfile-webhook .
docker images
docker build -t ${QUAY_REGISTRY}/aci-containers-certmanager:${IMAGE_TAG} --file=docker/travis/Dockerfile-certmanager .
docker images

# Note: acc-provision-operator and opflex images come from their respective repos
ALL_IMAGES="aci-containers-host aci-containers-controller cnideploy aci-containers-operator openvswitch aci-containers-webhook aci-containers-certmanager"

docker sbom --format spdx-json ${QUAY_REGISTRY}/opflex-build-base:${RELEASE_TAG_WITH_UPSTREAM_ID} | /tmp/grype
for IMAGE in ${ALL_IMAGES}; do
  docker sbom --format spdx-json ${QUAY_REGISTRY}/${IMAGE}:${IMAGE_TAG} | /tmp/grype
  docker sbom ${QUAY_REGISTRY}/${IMAGE}:${IMAGE_TAG}
done

for IMAGE in ${ALL_IMAGES}; do
  docker push ${QUAY_REGISTRY}/${IMAGE}:${IMAGE_TAG}
  docker tag ${QUAY_REGISTRY}/${IMAGE}:${IMAGE_TAG} ${QUAY_REGISTRY}/${IMAGE}:${IMAGE_TAG_DEV}
  docker push ${QUAY_REGISTRY}/${IMAGE}:${IMAGE_TAG_DEV}
done

git config --local user.name "travis-tagger"
git config --local user.email "sumitnaiksatam+travis-tagger@gmail.com"
git remote add travis-tagger https://travis-tagger:$TRAVIS_TAGGER@github.com/noironetworks/aci-containers.git
TAG_MESSAGE="ACI Release ${RELEASE_TAG} Created by Travis Job ${TRAVIS_JOB_NUMBER} ${TRAVIS_JOB_WEB_URL}" 

git tag -d ${TRAVIS_TAG}; git push travis-tagger :refs/tags/${TRAVIS_TAG}
git tag -f -a ${RELEASE_TAG} -m "${TAG_MESSAGE}"; git push travis-tagger -f --tags

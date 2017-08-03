#!/bin/bash
# Should be run from the root of the source tree
# Set env var REVISION to overwrite the 'revision' field in version string

BUILD_DIR=${BUILD_DIR:-`pwd`/debbuild}
mkdir -p $BUILD_DIR
rm -rf $BUILD_DIR/*
NAME=`python setup.py --name`
VERSION=`python setup.py --version`
REVISION=${REVISION:-1}
python setup.py sdist --dist-dir $BUILD_DIR
SOURCE_FILE=${NAME}-${VERSION}.tar.gz
tar -C $BUILD_DIR -xf $BUILD_DIR/$SOURCE_FILE
SOURCE_DIR=$BUILD_DIR/${NAME}-${VERSION}

sed -e "s/@VERSION@/$VERSION/" -e "s/@REVISION@/$REVISION/" ${SOURCE_DIR}/debian/changelog.in > ${SOURCE_DIR}/debian/changelog

mv $BUILD_DIR/$SOURCE_FILE $BUILD_DIR/${NAME}_${VERSION}.orig.tar.gz
pushd ${SOURCE_DIR}
debuild -d -us -uc
popd

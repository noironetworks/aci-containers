#!/bin/bash

set -e
set -x

if [ -z $REQUIRE_NAD_ANNOTATION ]; then
   REQUIRE_NAD_ANNOTATION=$false
elif [ "$REQUIRE_NAD_ANNOTATION" == "false" ]; then
   REQUIRE_NAD_ANNOTATION=$false
else
   REQUIRE_NAD_ANNOTATION="-require-nad-annotation"
fi

if [ -z $CONTAINER_FOR_ENVVARS ]; then
   CONTAINER_NAME_FOR_ENVVARS=$false
else
   CONTAINER_NAME_FOR_ENVVARS="-container-name-for-envvars "$CONTAINER_FOR_ENVVARS
fi

/usr/local/bin/aci-containers-webhook $REQUIRE_NAD_ANNOTATION $CONTAINER_NAME_FOR_ENVVARS

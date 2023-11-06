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

/usr/local/bin/aci-containers-webhook $REQUIRE_NAD_ANNOTATION

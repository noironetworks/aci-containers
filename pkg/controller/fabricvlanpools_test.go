package controller

import (
	"github.com/noironetworks/aci-containers/pkg/util"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestCombineVlanPools(t *testing.T) {
	nsVlanPoolMap1 := map[string]map[string]string{
		"aci-containers-system": {
			"default":    "[3023,3700-3701,3801,3804-3805,3826-3827,3829-3830,3840,3850-3852,3877-3879]",
			"additional": "[100]",
		},
		"default": {
			"test":       "[610]",
			"additional": "[3000]",
		},
	}
	combinedStr1 := util.CombineVlanPoolMaps(nsVlanPoolMap1, "aci-containers-system")
	elems := strings.Split(combinedStr1, ",")
	expectedStr1 := "3023,3700-3701,3801,3804-3805,3826-3827,3829-3830,3840,3850-3852,3877-3879,100"
	expectedElems := strings.Split(expectedStr1, ",")
	assert.Equal(t, len(elems), len(expectedElems), "namespace pool collect 1")

	combinedStr2 := util.CombineVlanPoolMaps(nsVlanPoolMap1, "default")
	elems = strings.Split(combinedStr2, ",")
	expectedStr2 := "610,3000"
	expectedElems = strings.Split(expectedStr2, ",")
	assert.Equal(t, len(elems), len(expectedElems), "namespace pool collect 2")

	combinedStr3 := util.CombineVlanPoolMaps(nsVlanPoolMap1, "")
	elems = strings.Split(combinedStr3, ",")
	expectedStr3 := "3023,3700-3701,3801,3804-3805,3826-3827,3829-3830,3840,3850-3852,3877-3879,100,610,3000"
	expectedElems = strings.Split(expectedStr3, ",")
	assert.Equal(t, len(elems), len(expectedElems), "global pool collect")
}

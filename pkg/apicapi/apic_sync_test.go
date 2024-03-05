// Copyright 2017 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apicapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApicBodyAttrCmp(t *testing.T) {
	server := newTestServer()
	defer server.server.Close()
	conn, err := server.testConn(nil)
	assert.Nil(t, err)

	t.Run("No Metadata for Class", func(t *testing.T) {
		class := "fvTenant1"
		bodyc := &ApicObjectBody{}
		bodyd := &ApicObjectBody{}

		result := conn.apicBodyAttrCmp(class, bodyc, bodyd)

		assert.True(t, result)
	})

	t.Run("Matching Attributes", func(t *testing.T) {
		class := "vzRsSubjGraphAtt"
		bodyc := &ApicObjectBody{
			Attributes: map[string]interface{}{
				"tnVnsAbsGraphName": "graph1",
			},
		}
		bodyd := &ApicObjectBody{
			Attributes: map[string]interface{}{
				"tnVnsAbsGraphName": "graph1",
			},
		}

		result := conn.apicBodyAttrCmp(class, bodyc, bodyd)

		assert.True(t, result)
	})

	t.Run("Mismatching Attributes", func(t *testing.T) {
		class := "vzRsSubjGraphAtt"
		bodyc := &ApicObjectBody{
			Attributes: map[string]interface{}{
				"tnVnsAbsGraphName": "graph1",
			},
		}
		bodyd := &ApicObjectBody{
			Attributes: map[string]interface{}{
				"tnVnsAbsGraphName": "graph2",
			},
		}

		result := conn.apicBodyAttrCmp(class, bodyc, bodyd)

		assert.False(t, result)
	})

	t.Run("Ignoring Comparison of tnVnsAbsGraphName", func(t *testing.T) {
		class := "vzRsSubjGraphAtt"
		bodyc := &ApicObjectBody{
			Attributes: map[string]interface{}{
				"tnVnsAbsGraphName": "graph1",
				"forceResolve":      true,
			},
		}
		bodyd := &ApicObjectBody{
			Attributes: map[string]interface{}{
				"tnVnsAbsGraphName": "graph2",
				"customSG":          true,
			},
		}

		result := conn.apicBodyAttrCmp(class, bodyc, bodyd)

		assert.True(t, result)
	})

	t.Run("Matching Annotation", func(t *testing.T) {
		class := "tagAnnotation"
		bodyc := &ApicObjectBody{
			Attributes: map[string]interface{}{
				"annotation": "annotation1",
			},
		}
		bodyd := &ApicObjectBody{
			Attributes: map[string]interface{}{
				"annotation": "annotation1",
			},
		}

		result := conn.apicBodyAttrCmp(class, bodyc, bodyd)

		assert.True(t, result)
	})

	t.Run("Mismatching Annotation", func(t *testing.T) {
		class := "fvTenant"
		bodyc := &ApicObjectBody{
			Attributes: map[string]interface{}{
				"annotation": "annotation1",
			},
		}
		bodyd := &ApicObjectBody{
			Attributes: map[string]interface{}{
				"annotation": "annotation2",
			},
		}

		result := conn.apicBodyAttrCmp(class, bodyc, bodyd)

		assert.False(t, result)
	})
}

func TestApicCntCmp(t *testing.T) {
	server := newTestServer()
	defer server.server.Close()
	conn, err := server.testConn(nil)
	assert.Nil(t, err)

	t.Run("Matching Objects", func(t *testing.T) {
		current := ApicObject{
			"vzRsSubjGraphAtt": &ApicObjectBody{
				Attributes: map[string]interface{}{
					"tnVnsAbsGraphName": "graph1",
				},
			},
		}
		desired := ApicObject{
			"vzRsSubjGraphAtt": &ApicObjectBody{
				Attributes: map[string]interface{}{
					"tnVnsAbsGraphName": "graph1",
				},
			},
		}

		result := conn.apicCntCmp(current, desired)

		assert.True(t, result)
	})

	t.Run("Mismatching Objects", func(t *testing.T) {
		current := ApicObject{
			"vzRsSubjGraphAtt": &ApicObjectBody{
				Attributes: map[string]interface{}{
					"tnVnsAbsGraphName": "graph1",
				},
			},
		}
		desired := ApicObject{
			"vzRsSubjGraphAtt": &ApicObjectBody{
				Attributes: map[string]interface{}{
					"tnVnsAbsGraphName": "graph2",
				},
			},
		}

		result := conn.apicCntCmp(current, desired)

		assert.False(t, result)
	})

	t.Run("Invalid Comparison", func(t *testing.T) {
		current := ApicObject{
			"vzRsSubjGraphAtt": &ApicObjectBody{
				Attributes: map[string]interface{}{
					"tnVnsAbsGraphName": "graph1",
				},
			},
		}
		desired := ApicObject{
			"vzRsSubjGraphAtt2": &ApicObjectBody{
				Attributes: map[string]interface{}{
					"tnVnsAbsGraphName": "graph1",
				},
			},
		}

		result := conn.apicCntCmp(current, desired)

		assert.False(t, result)
	})
}

func TestCheckNonDeletable(t *testing.T) {
	server := newTestServer()
	defer server.server.Close()
	conn, err := server.testConn(nil)
	assert.Nil(t, err)

	t.Run("Non-Deletable Class", func(t *testing.T) {
		class := "infraGeneric"
		expected := false

		result := conn.checkNonDeletable(class)

		assert.Equal(t, expected, result)
	})

	t.Run("Deletable Class", func(t *testing.T) {
		class := "fvTenant"
		expected := true

		result := conn.checkNonDeletable(class)

		assert.Equal(t, expected, result)
	})

	t.Run("Unknown Class", func(t *testing.T) {
		class := "unknownClass"
		expected := true

		result := conn.checkNonDeletable(class)

		assert.Equal(t, expected, result)
	})
}
func TestRemoveFromDnIndex(t *testing.T) {
	server := newTestServer()
	defer server.server.Close()
	conn, err := server.testConn(nil)
	assert.Nil(t, err)

	t.Run("Empty DN", func(t *testing.T) {
		dn := ""
		conn.removeFromDnIndex(dn)
		assert.Empty(t, conn.desiredStateDn)
	})

	t.Run("Existing DN", func(t *testing.T) {
		dn := "dn1"
		childDn := "childDn1"
		obj := ApicObject{
			"class": &ApicObjectBody{
				Attributes: map[string]interface{}{
					"dn": dn,
				},
				Children: ApicSlice{
					ApicObject{
						"class": &ApicObjectBody{
							Attributes: map[string]interface{}{
								"dn": childDn,
							},
						},
					},
				},
			},
		}
		conn.desiredStateDn[dn] = obj
		conn.desiredStateDn[childDn] = obj["class"].Children[0]

		conn.removeFromDnIndex(dn)

		_, ok := conn.desiredStateDn[dn]
		assert.False(t, ok)

		_, ok = conn.desiredStateDn[childDn]
		assert.False(t, ok)

		assert.Empty(t, conn.desiredStateDn)
	})
}

func TestClearApicContainer(t *testing.T) {
	server := newTestServer()
	defer server.server.Close()
	conn, err := server.testConn(nil)
	assert.Nil(t, err)

	t.Run("Clear Apic Container", func(t *testing.T) {
		key := "containerKey"

		conn.ClearApicContainer(key)

		assert.Nil(t, conn.desiredStateDn[key])
	})
}

func TestClearApicObjects(t *testing.T) {
	server := newTestServer()
	defer server.server.Close()
	conn, err := server.testConn(nil)
	assert.Nil(t, err)

	t.Run("Clear Apic Objects", func(t *testing.T) {
		key := "containerKey"

		conn.ClearApicObjects(key)

		assert.Nil(t, conn.desiredStateDn[key])
	})
}
func TestWriteStaticApicObjects(t *testing.T) {
	server := newTestServer()
	defer server.server.Close()
	conn, err := server.testConn(nil)
	assert.Nil(t, err)

	t.Run("Write Static Apic Objects", func(t *testing.T) {
		key := "containerKey"
		objects := ApicSlice{
			ApicObject{
				"vzRsSubjGraphAtt": &ApicObjectBody{
					Attributes: map[string]interface{}{
						"tnVnsAbsGraphName": "graph1",
					},
				},
			},
			ApicObject{
				"vzRsSubjGraphAtt": &ApicObjectBody{
					Attributes: map[string]interface{}{
						"tnVnsAbsGraphName": "graph2",
					},
				},
			},
		}

		conn.WriteStaticApicObjects(key, objects)
		assert.Equal(t, objects, conn.desiredState[key])
	})
}

func TestCheckDeletes(t *testing.T) {
	server := newTestServer()
	defer server.server.Close()
	conn, err := server.testConn(nil)
	assert.Nil(t, err)

	t.Run("Delete Hook Called", func(t *testing.T) {
		delHook1Called := false
		delHook2Called := false
		oldState := make(map[string]map[string]bool)
		oldState["dn1"] = map[string]bool{"id1": true, "id2": true}
		conn.subscriptions.ids["id1"] = "value1"
		conn.subscriptions.ids["id2"] = "value2"
		conn.subscriptions.subs["value1"] = &subscription{
			deleteHook: func(dn string) {
				delHook1Called = true
			},
		}
		conn.subscriptions.subs["value2"] = &subscription{
			deleteHook: func(dn string) {
				delHook2Called = true
			},
		}

		conn.checkDeletes(oldState)

		assert.True(t, delHook1Called)
		assert.True(t, delHook2Called)
	})

	t.Run("Delete Hook not Called", func(t *testing.T) {
		delHook1Called := false
		delHook2Called := false
		oldState := make(map[string]map[string]bool)
		oldState["dn2"] = map[string]bool{"id1": true, "id2": true}
		conn.cacheDnSubIds["dn2"] = map[string]bool{"id1": true, "id2": true}
		conn.subscriptions.ids["id1"] = "value1"
		conn.subscriptions.ids["id2"] = "value2"
		conn.subscriptions.subs["value1"] = &subscription{
			deleteHook: func(dn string) {
				delHook1Called = true
			},
		}
		conn.subscriptions.subs["value2"] = &subscription{
			deleteHook: func(dn string) {
				delHook2Called = true
			},
		}

		conn.checkDeletes(oldState)

		assert.False(t, delHook1Called)
		assert.False(t, delHook2Called)
	})
}

func TestDoWriteApicObjects(t *testing.T) {
	server := newTestServer()
	defer server.server.Close()
	conn, err := server.testConn(nil)
	assert.Nil(t, err)

	conn.desiredState = map[string]ApicSlice{
		"key1": {
			ApicObject{
				"class": &ApicObjectBody{
					Attributes: map[string]interface{}{
						"attr1": "value1",
						"dn":    "dn1",
					},
				},
			},
		},
	}

	key := "key1"
	objects := ApicSlice{
		ApicObject{
			"class": &ApicObjectBody{
				Attributes: map[string]interface{}{
					"attr2": "value2",
					"dn":    "dn2",
				},
			},
		},
	}

	conn.doWriteApicObjects(key, objects, true, false)

	expectedDesiredState := map[string]ApicSlice{
		"key1": {
			ApicObject{
				"class": &ApicObjectBody{
					Attributes: map[string]interface{}{
						"annotation": "orchestrator:aci-containers-controller",
						"attr2":      "value2",
						"dn":         "dn2",
					},
					Children: ApicSlice{
						ApicObject{
							"tagAnnotation": &ApicObjectBody{
								Attributes: map[string]interface{}{
									"dn":    "dn2/annotationKey-aci-containers-controller-tag",
									"key":   "aci-containers-controller-tag",
									"value": "kube-8174099687a26621f4e2cdd7cc03b3da",
								},
							},
						},
					},
				},
			},
		},
	}
	assert.Equal(t, expectedDesiredState, conn.desiredState)

	expectedContainerDns := map[string]bool{
		"dn2": true,
	}
	assert.Equal(t, expectedContainerDns, conn.containerDns)

	for k := range conn.desiredStateDn {
		assert.Contains(t, k, "dn2")
	}

	conn.doWriteApicObjects(key, nil, true, false)
	assert.Empty(t, conn.desiredState)
	assert.Empty(t, conn.keyHashes)
	assert.Empty(t, conn.containerDns)
}

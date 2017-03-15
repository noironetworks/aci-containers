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

package controller

import (
	"sort"
	"testing"
	"time"

	tu "github.com/noironetworks/aci-containers/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

type uniqueNameTest struct {
	components []string
	result     string
	desc       string
}

var uniqueNameTests = []uniqueNameTest{
	{[]string{}, "z23tosoitfutobxn4hrqzgjjwp6v3wjgcy4ddqx3rpkb43x3ceta", "empty"},
	{[]string{"a", "b", "c"}, "xz4j2rrayb4ebrjdzc4rmrudirw6sp7bggcpjrihdav4zrw3mtnq", "simple"},
	{[]string{"0", "1", "9"}, "esy7rw6xsfko2pbtocshyccpkcni7rrsngh7wehjskc66pgh2gha", "numbers"},
	{[]string{"AA", "BB", "ZZ"}, "ksult6xm2m6vu47vcmwfvsly27x7ai4whduys5mruzcn5qogs6pq", "caps"},
	{[]string{"a -", "-", "_"}, "vvxojw5rwlmq6abg3trx6nchbffez4lxfhalgidxlyhtlh3r4jwq", "sym"},
}

func TestUniqueName(t *testing.T) {
	for _, at := range uniqueNameTests {
		assert.Equal(t, at.result,
			aimGenerateUniqueName("test", at.components...), at.desc)
	}
}

type indexDiffTest struct {
	ktype      string
	key        string
	objects    aciSlice
	expAdds    aciSlice
	expUpdates aciSlice
	expDeletes []string
	desc       string
}

func setDispName(displayName string, aci *Aci) *Aci {
	aci.Spec.SecurityGroup.DisplayName = displayName
	return aci
}

var indexDiffTests = []indexDiffTest{
	{"sec-group", "a", nil, nil, nil, nil, "empty"},
	{"sec-group", "a",
		aciSlice{NewSecurityGroup("common", "test")},
		aciSlice{NewSecurityGroup("common", "test")},
		nil, nil, "add"},
	{"sec-group", "a",
		aciSlice{setDispName("test", NewSecurityGroup("common", "test"))},
		nil,
		aciSlice{setDispName("test", NewSecurityGroup("common", "test"))},
		nil, "update"},
	{"sec-group", "a", nil, nil, nil,
		[]string{aimGenerateUniqueName("security_group", "test", "common")},
		"delete"},
	{"sec-group", "a",
		aciSlice{
			NewSecurityGroup("common", "test1"),
			NewSecurityGroup("common", "test2"),
			NewSecurityGroup("common", "test3"),
			NewSecurityGroup("common", "test4"),
		},
		aciSlice{
			NewSecurityGroup("common", "test1"),
			NewSecurityGroup("common", "test2"),
			NewSecurityGroup("common", "test3"),
			NewSecurityGroup("common", "test4"),
		},
		nil, nil, "addmultiple"},
	{"sec-group", "a",
		aciSlice{
			NewSecurityGroup("common", "test1"),
			NewSecurityGroup("common", "test4"),
			NewSecurityGroup("common", "test3"),
			NewSecurityGroup("common", "test2"),
		},
		nil, nil, nil, "nochange"},
	{"sec-group", "a",
		aciSlice{
			NewSecurityGroup("common", "test1"),
			NewSecurityGroup("common", "test0"),
			setDispName("test2", NewSecurityGroup("common", "test2")),
			NewSecurityGroup("common", "test3"),
			NewSecurityGroup("common", "test5"),
		},
		aciSlice{
			NewSecurityGroup("common", "test0"),
			NewSecurityGroup("common", "test5"),
		},
		aciSlice{
			setDispName("test2", NewSecurityGroup("common", "test2")),
		},
		[]string{aimGenerateUniqueName("security_group", "test4", "common")},
		"mixed"},
	{"sec-group", "b",
		aciSlice{
			NewSecurityGroup("common", "septest"),
		},
		aciSlice{
			NewSecurityGroup("common", "septest"),
		},
		nil, nil, "diffkey"},
}

func TestAimIndexDiff(t *testing.T) {
	cont := testController()
	cont.run()

	for _, it := range indexDiffTests {
		cont.aimAdds = nil
		cont.aimUpdates = nil
		cont.aimDeletes = nil
		fixAciSlice(it.expAdds, it.ktype, it.key)
		fixAciSlice(it.expUpdates, it.ktype, it.key)

		cont.writeAimObjects(it.ktype, it.key, it.objects)
		assert.Equal(t, it.expAdds, cont.aimAdds, "adds", it.desc)
		assert.Equal(t, it.expUpdates, cont.aimUpdates, "updates", it.desc)
		assert.Equal(t, it.expDeletes, cont.aimDeletes, "deletes", it.desc)
	}

	cont.stop()
}

func fixAciSlice(slice aciSlice, ktype string, key string) {
	sort.Sort(slice)
	for _, o := range slice {
		addAimLabels(ktype, key, o)
	}
}

func staticGlobalKey() aimKey {
	return aimKey{"Controller", "static"}
}

func TestAimFullSync(t *testing.T) {

	i := 0
	j := 1
	for j < len(indexDiffTests)-1 { // last test case doesn't apply to this
		cont := testController()

		it := &indexDiffTests[i]

		for _, o := range it.objects {
			addAimLabels(it.ktype, it.key, o)
			cont.fakeAimSource.Add(o)
		}

		cont.run()

		it = &indexDiffTests[j]
		cont.writeAimObjects(it.ktype, it.key, it.objects)
		cont.aimAdds = nil
		cont.aimUpdates = nil
		cont.aimDeletes = nil

		cont.aimFullSync()

		for _, o := range it.expAdds {
			addAimLabels(it.ktype, it.key, o)
		}
		for _, o := range it.expUpdates {
			addAimLabels(it.ktype, it.key, o)
		}

		static := cont.staticNetPolObjs()
		fixAciSlice(static, staticNetPolKey().ktype, staticNetPolKey().key)
		it.expAdds = append(it.expAdds, static...)
		static = cont.globalStaticObjs()
		fixAciSlice(static, staticGlobalKey().ktype, staticGlobalKey().key)
		it.expAdds = append(it.expAdds, static...)

		sort.Sort(it.expAdds)
		sort.Sort(cont.aimAdds)

		assert.Equal(t, it.expAdds, cont.aimAdds, "adds", it.desc)
		assert.Equal(t, it.expUpdates, cont.aimUpdates, "updates", it.desc)
		assert.Equal(t, it.expDeletes, cont.aimDeletes, "deletes", it.desc)

		i++
		j++

		cont.stop()
	}

}

func TestAimReconcile(t *testing.T) {
	test := aciSlice{
		NewSecurityGroupRule("common", "test1", "np", "a"),
		NewSecurityGroupRule("common", "test2", "np", "a"),
		NewSecurityGroupRule("common", "test3", "np", "a"),
		NewSecurityGroupRule("common", "test4", "np", "a"),
	}
	fixAciSlice(test, "Reconcile", "a")

	cont := testController()
	cont.run()

	cont.writeAimObjects("Reconcile", "a", test)

	{
		cont.aimAdds = nil
		cont.aimUpdates = nil
		cont.aimDeletes = nil

		update := NewSecurityGroupRule("common",
			test[1].Spec.SecurityGroupRule.SecurityGroupName, "np", "a")
		update.Spec.SecurityGroupRule.Ethertype = "ipv4"
		addAimLabels("Reconcile", "a", update)
		cont.fakeAimSource.Add(update)

		tu.WaitFor(t, "unexpectedmod", 500*time.Millisecond,
			func(last bool) (bool, error) {
				return tu.WaitEqual(t, last, aciSlice{test[1]},
					cont.aimUpdates, "unexpectedmod", "updates"), nil
			})
		assert.Nil(t, cont.aimDeletes, "unexpectedmod", "deletes")
		assert.Nil(t, cont.aimAdds, "unexpectedmod", "adds")
	}

	{
		cont.aimAdds = nil
		cont.aimUpdates = nil
		cont.aimDeletes = nil

		update := NewSecurityGroupRule("common", "wtf", "np", "a")
		addAimLabels("Reconcile", "a", update)
		cont.fakeAimSource.Add(update)

		tu.WaitFor(t, "unexpectedadd", 500*time.Millisecond,
			func(last bool) (bool, error) {
				return tu.WaitEqual(t, last, []string{update.ObjectMeta.Name},
					cont.aimDeletes, "unexpectedadd", "deleted"), nil
			})
		assert.Nil(t, cont.aimUpdates, "unexpectedadd", "updates")
		assert.Nil(t, cont.aimAdds, "unexpectedadd", "adds")
	}

	{
		cont.aimAdds = nil
		cont.aimUpdates = nil
		cont.aimDeletes = nil

		cont.fakeAimSource.Delete(test[1])

		tu.WaitFor(t, "unexpecteddelete", 500*time.Millisecond,
			func(last bool) (bool, error) {
				return tu.WaitEqual(t, last, aciSlice{test[1]},
					cont.aimAdds, "unexpecteddelete", "adds"), nil
			})
		assert.Nil(t, cont.aimDeletes, "unexpecteddelete", "deletes")
		assert.Nil(t, cont.aimUpdates, "unexpecteddelete", "updates")
	}

	cont.stop()
}

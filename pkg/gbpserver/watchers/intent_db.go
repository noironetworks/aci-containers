/***
Copyright 2019 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package watchers

import (
	"fmt"
	"github.com/sirupsen/logrus"
	//"github.com/davecgh/go-spew/spew"
	"github.com/noironetworks/aci-containers/pkg/gbpcrd/apis/acipolicy/v1"
	"github.com/noironetworks/aci-containers/pkg/gbpserver"
	"reflect"
	"sync"
)

// keeps track of the dependency of the intent objects so appropriate
// updates can be generated when one of them changes.
type intentDB struct {
	sync.Mutex
	log       *logrus.Entry
	gs        *gbpserver.Server
	filters   map[string]*filterNode
	contracts map[string]*contractNode
	epgs      map[string]*epgNode
}

func newIntentDB(gs *gbpserver.Server, log *logrus.Entry) *intentDB {
	return &intentDB{
		log:       log,
		gs:        gs,
		filters:   make(map[string]*filterNode),
		contracts: make(map[string]*contractNode),
		epgs:      make(map[string]*epgNode),
	}
}

func (idb *intentDB) saveEPG(e *gbpserver.EPG) {
	idb.Lock()
	defer idb.Unlock()
	en := &epgNode{epg: e}
	// if nothing changed, just ignore
	curr := idb.epgs[en.name()]
	if reflect.DeepEqual(en, curr) {
		idb.log.Debugf("saveEPG: %s unchanged", en.name())
		return
	}

	idb.epgs[en.name()] = en
	// save the refs
	adder := func(c string) {
		cnode := idb.contracts[c]
		if cnode == nil {
			// add an empty contract node with just the refs
			cnode = newContractNode()
		}
		idb.contracts[c] = cnode
		cnode.addRef(en)
	}

	for _, c := range e.ConsContracts {
		adder(c)
	}

	for _, p := range e.ProvContracts {
		adder(p)
	}

	en.trickle(idb, true)
}

func (idb *intentDB) deleteEPG(e *gbpserver.EPG) {
	idb.Lock()
	defer idb.Unlock()
	en := &epgNode{epg: e}
	curr := idb.epgs[en.name()]
	if curr == nil {
		idb.log.Debugf("Epg %s not found", en.name())
		return
	}
	delete(idb.epgs, en.name())
	// delete contract refs
	for _, cn := range idb.contracts {
		cn.delRef(en.name())
	}

	curr.trickle(idb, false)
}

func (idb *intentDB) saveApicContract(c *apicContract) {
	idb.Lock()
	defer idb.Unlock()
	cn := newContractNode()
	cn.a = c
	//add filter refs
	for _, f := range idb.filters {
		f.delRef(cn.name())
	}

	for _, f := range c.Filters {
		fn := idb.filters[f]
		if fn == nil {
			fn = &filterNode{fName: f, refs: make(map[string]*contractNode)}
			idb.filters[f] = fn
		}

		fn.addRef(cn)
	}
	idb.saveContract(cn)
}

func (idb *intentDB) deleteApicContract(c *apicContract) {
	idb.Lock()
	defer idb.Unlock()
	cn := newContractNode()
	cn.a = c
	for _, f := range idb.filters {
		f.delRef(cn.name())
	}
	idb.deleteContract(cn)
}

func (idb *intentDB) saveGbpContract(c *gbpserver.Contract) {
	idb.Lock()
	defer idb.Unlock()
	cn := newContractNode()
	cn.g = c
	idb.saveContract(cn)
}

func (idb *intentDB) deleteGbpContract(c *gbpserver.Contract) {
	idb.Lock()
	defer idb.Unlock()
	cn := newContractNode()
	cn.g = c
	idb.deleteContract(cn)
}

func (idb *intentDB) saveContract(cn *contractNode) {
	// if nothing changed, just ignore
	curr := idb.contracts[cn.name()]
	if curr != nil {
		cn.refs = curr.refs
	}

	if reflect.DeepEqual(cn, curr) {
		idb.log.Debugf("saveContract: %s unchanged", cn.name())
		return
	}

	idb.contracts[cn.name()] = cn
	cn.trickle(idb, true)
}

func (idb *intentDB) deleteContract(cn *contractNode) {
	curr := idb.contracts[cn.name()]
	if curr != nil {
		delete(idb.contracts, cn.name())
		curr.trickle(idb, false)
	}
}

func (idb *intentDB) saveFilter(name string, rules []v1.WLRule) {
	idb.Lock()
	defer idb.Unlock()
	fn := &filterNode{fName: name, rules: rules}

	curr := idb.filters[fn.name()]
	if curr != nil {
		fn.refs = curr.refs
	}

	if reflect.DeepEqual(curr, fn) {
		idb.log.Debugf("Filter %s unchanged", name)
		return
	}

	// filters stay at the intent layer and get merged with contracts downstream
	idb.filters[fn.name()] = fn
	fn.trickle(idb, true)
}

func (idb *intentDB) deleteFilter(name string) {
	idb.Lock()
	defer idb.Unlock()
	curr := idb.filters[name]
	if curr == nil {
		idb.log.Debugf("Filter %s not found", name)
		return
	}

	// filters stay at the intent layer and get merged with contracts downstream
	delete(idb.filters, name)
	curr.trickle(idb, false)
}

// a db node has references to direct dependents, knows to trickle down an update
// the interface definition is used only for reference as we need to hardcode the
// relationships to match the apic model.
type dbNode interface {
	name() string
	addRef(node dbNode)
	delRef(to string)
	trickle(idb *intentDB, add bool)
}

// filterNode implements a dbNode around a filter
type filterNode struct {
	fName string
	rules []v1.WLRule
	refs  map[string]*contractNode
}

func (f *filterNode) name() string {
	return f.fName
}

func (f *filterNode) addRef(n *contractNode) {
	f.refs[n.name()] = n
}

func (f *filterNode) delRef(to string) {
	delete(f.refs, to)
}

func (f *filterNode) trickle(idb *intentDB, add bool) {
	for _, r := range f.refs {
		r.trickle(idb, add)
	}
}

// contractNode implements a dbNode around a contract
// the node might contain either an apic contract from which
// the gbpcontract can be derived, or a gbpcontract directly
// in case of a mode without apic
type contractNode struct {
	a    *apicContract
	g    *gbpserver.Contract
	refs map[string]*epgNode
}

func newContractNode() *contractNode {
	return &contractNode{refs: make(map[string]*epgNode)}
}

type apicContract struct {
	Tenant  string
	Name    string
	Filters []string
}

func (c *contractNode) name() string {
	if c.a != nil {
		return fmt.Sprintf("%s/%s", c.a.Tenant, c.a.Name)
	}

	if c.g != nil {
		return fmt.Sprintf("%s/%s", c.g.Tenant, c.g.Name)
	}

	return "missing"
}

func (c *contractNode) addRef(e *epgNode) {
	c.refs[e.name()] = e
}

func (c *contractNode) delRef(to string) {
	delete(c.refs, to)
}

func (c *contractNode) trickle(idb *intentDB, add bool) {
	// resolve the contract
	if c.a == nil && c.g == nil {
		idb.log.Debugf("Contract not present yet")
		return
	}

	var ct *gbpserver.Contract
	var resolved bool

	if c.g != nil {
		ct, resolved = c.g, true
	} else {
		// create the gbp contract
		ct, resolved = c.a.genGbpContract(idb)
	}

	if add && resolved {
		idb.gs.AddContract(*ct)
	} else { // unresolved add is also a delete
		idb.gs.DelContract(*ct)
	}

	for _, r := range c.refs {
		r.trickle(idb, true)
	}
}

func (a *apicContract) genGbpContract(idb *intentDB) (*gbpserver.Contract, bool) {
	resolved := true // lets be optimistic
	g := &gbpserver.Contract{
		Tenant: a.Tenant,
		Name:   a.Name,
	}

	for _, f := range a.Filters {
		r, ok := idb.filters[f]
		if !ok {
			idb.log.Infof("%s unresolved Filter %s not found", a.Name, f)
			resolved = false
			break
		}

		if r.rules == nil {
			idb.log.Infof("%s unresolved Rule for %s not found", a.Name, f)
			resolved = false
		}

		g.AllowList = append(g.AllowList, r.rules...)
	}
	return g, resolved
}

// epgNode implements a dbNode around an epg
type epgNode struct {
	epg *gbpserver.EPG
}

func (e *epgNode) name() string {
	return fmt.Sprintf("%s/%s", e.epg.Tenant, e.epg.Name)
}

func (e *epgNode) addRef(to dbNode) {
}

func (e *epgNode) delRef(to string) {
}

func (e *epgNode) trickle(idb *intentDB, add bool) {
	// just push the epg
	if add {
		idb.gs.AddEPG(*e.epg)
	} else {
		idb.gs.DelEPG(*e.epg)
	}
}

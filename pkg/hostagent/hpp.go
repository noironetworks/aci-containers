// Copyright 2019 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRATIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Handlers for hpp updates.

package hostagent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-cmp/cmp"
	hppv1 "github.com/noironetworks/aci-containers/pkg/hpp/apis/aci.hpp/v1"
	hppclset "github.com/noironetworks/aci-containers/pkg/hpp/clientset/versioned"
	"github.com/noironetworks/aci-containers/pkg/util"

	"github.com/sirupsen/logrus"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	controller "k8s.io/kubernetes/pkg/controller"
)

// Test counters for measuring informer event noise — remove after testing.
var (
	HppUpdateTotal    atomic.Int64
	HppUpdateNoChange atomic.Int64
	RicUpdateTotal    atomic.Int64
	RicUpdateNoChange atomic.Int64
	NetpolFileWrites  atomic.Int64
	NetpolFileSkips   atomic.Int64
)

// Test scaffolding: buffer the old-vs-new Spec diffs of HPP/RIC updates that
// were counted as changes, so they can be dumped alongside the periodic update
// stats log line — remove after testing.
var (
	updateDiffMutex sync.Mutex
	updateDiffs     []string
)

// recordUpdateDiff appends a human-readable diff for a change-counted update.
func recordUpdateDiff(kind, name, diff string) {
	updateDiffMutex.Lock()
	updateDiffs = append(updateDiffs, fmt.Sprintf("%s %s changed:\n%s", kind, name, diff))
	updateDiffMutex.Unlock()
}

// drainUpdateDiffs returns and clears the buffered update diffs.
func drainUpdateDiffs() []string {
	updateDiffMutex.Lock()
	diffs := updateDiffs
	updateDiffs = nil
	updateDiffMutex.Unlock()
	return diffs
}

// hostAgentStartTime records when this process started. Used by stale tmp-file
// cleanup in syncLocalHppMo: only tmp files with mtime before this time can
// safely be removed (they must be leftovers from a prior crashed process, not
// an in-flight write from the current one).
var hostAgentStartTime = time.Now()

func (agent *HostAgent) initHppInformerFromClient(
	hppClient *hppclset.Clientset) {
	agent.initHppInformerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return hppClient.AciV1().HostprotPols(metav1.NamespaceAll).List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return hppClient.AciV1().HostprotPols(metav1.NamespaceAll).Watch(context.TODO(), options)
			},
		})
}

func (agent *HostAgent) initHostprotRemoteIpContainerInformerFromClient(
	hppClient *hppclset.Clientset) {
	agent.initHostprotRemoteIpContainerBase(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return hppClient.AciV1().HostprotRemoteIpContainers(metav1.NamespaceAll).List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return hppClient.AciV1().HostprotRemoteIpContainers(metav1.NamespaceAll).Watch(context.TODO(), options)
			},
		})
}

func (agent *HostAgent) hppDirectEnabled() bool {
	return agent.config.EnableHppDirect &&
		!agent.config.DisableHppRendering &&
		!agent.config.ChainedMode
}

func HppLogger(log *logrus.Logger, hpp *hppv1.HostprotPol) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": hpp.ObjectMeta.Namespace,
		"name":      hpp.ObjectMeta.Name,
	})
}

func HostprotRemoteIpContainerLogger(log *logrus.Logger, hpp *hppv1.HostprotRemoteIpContainer) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"namespace": hpp.ObjectMeta.Namespace,
		"name":      hpp.ObjectMeta.Name,
	})
}

func (agent *HostAgent) initHppInformerBase(listWatch *cache.ListWatch) {
	agent.hppInformer = cache.NewSharedIndexInformer(
		listWatch,
		&hppv1.HostprotPol{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	reg, err := agent.hppInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			hpp := obj.(*hppv1.HostprotPol)
			agent.handleHppAdd(hpp)
		},
		UpdateFunc: func(old interface{}, obj interface{}) {
			HppUpdateTotal.Add(1)
			oldHpp, ok1 := old.(*hppv1.HostprotPol)
			newHpp, ok2 := obj.(*hppv1.HostprotPol)
			if ok1 && ok2 && reflect.DeepEqual(oldHpp.Spec, newHpp.Spec) {
				HppUpdateNoChange.Add(1)
				return
			}
			if ok1 && ok2 {
				if diff := cmp.Diff(oldHpp.Spec, newHpp.Spec); diff != "" {
					recordUpdateDiff("HPP", newHpp.Name, diff)
				}
			}
			agent.handleHppUpdate(oldHpp, newHpp)
		},
		DeleteFunc: func(obj interface{}) {
			hpp, ok := obj.(*hppv1.HostprotPol)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					agent.log.Error("hppDelete: unexpected object type")
					return
				}
				hpp, ok = tombstone.Obj.(*hppv1.HostprotPol)
				if !ok {
					agent.log.Error("hppDelete: tombstone contained non-HPP object")
					return
				}
			}
			agent.handleHppDelete(hpp)
		},
	})
	if err != nil {
		agent.log.Errorf("Failed to register hpp event handler: %v", err)
		return
	}
	agent.hppInformerReg = reg
}

func (agent *HostAgent) initHostprotRemoteIpContainerBase(listWatch *cache.ListWatch) {
	agent.hppRemoteIpInformer = cache.NewSharedIndexInformer(
		listWatch,
		&hppv1.HostprotRemoteIpContainer{},
		controller.NoResyncPeriodFunc(),
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	agent.hppRemoteIpInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			agent.ricChanged(obj)
		},
		UpdateFunc: func(old interface{}, obj interface{}) {
			RicUpdateTotal.Add(1)
			oldRic, ok1 := old.(*hppv1.HostprotRemoteIpContainer)
			newRic, ok2 := obj.(*hppv1.HostprotRemoteIpContainer)
			if ok1 && ok2 && reflect.DeepEqual(oldRic.Spec, newRic.Spec) {
				RicUpdateNoChange.Add(1)
				return
			}
			if ok1 && ok2 {
				if diff := cmp.Diff(oldRic.Spec, newRic.Spec); diff != "" {
					recordUpdateDiff("RIC", newRic.Name, diff)
				}
			}
			agent.ricChanged(obj)
		},
		DeleteFunc: func(obj interface{}) {
			agent.ricChanged(obj)
		},
	})
}

// ricChanged handles RIC informer events — looks up HPPs by k8s key and re-renders them.
func (agent *HostAgent) ricChanged(obj interface{}) {
	ric, ok := obj.(*hppv1.HostprotRemoteIpContainer)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			agent.log.Error("ricChanged: unexpected object type")
			return
		}
		ric, ok = tombstone.Obj.(*hppv1.HostprotRemoteIpContainer)
		if !ok {
			agent.log.Error("ricChanged: tombstone contained non-RIC object")
			return
		}
	}

	agent.hppMutex.Lock()
	hppKeys := agent.ricToHpp[ric.Name]
	keys := make([]string, 0, len(hppKeys))
	for key := range hppKeys {
		keys = append(keys, key)
	}
	agent.hppMutex.Unlock()

	for _, key := range keys {
		obj, exists, err := agent.hppInformer.GetIndexer().GetByKey(key)
		if err != nil || !exists {
			continue
		}
		if hpp, ok := obj.(*hppv1.HostprotPol); ok {
			agent.hppMutex.Lock()
			agent.queueHppIfLocal(hpp)
			agent.hppMutex.Unlock()
		}
	}
}

func (agent *HostAgent) getHostprotRemoteIpContainer(name, ns string) (*hppv1.HostprotRemoteIpContainer, error) {
	key := ns + "/" + name
	obj, exists, err := agent.hppRemoteIpInformer.GetIndexer().GetByKey(key)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("HostprotRemoteIpContainer %s not found", name)
	}
	ric, ok := obj.(*hppv1.HostprotRemoteIpContainer)
	if !ok {
		return nil, fmt.Errorf("failed to cast object to HostprotRemoteIpContainer")
	}
	return ric, nil
}

// isHppLocallyRelevant determines if an HPP should be materialized on this node.
// Static policies and this node's node policy are always local. NP-derived HPPs
// are local only if a matching NetworkPolicy selects pods running on this node.
func (agent *HostAgent) isHppLocallyRelevant(hpp *hppv1.HostprotPol) bool {
	specName := hpp.Spec.Name

	// Static policies and this node's node policy — always local.
	if agent.isStaticOrNodeHpp(specName) {
		return true
	}

	// NP-derived: check if any referenced NP selects pods on this node.
	for _, npkey := range hpp.Spec.NetworkPolicies {
		if len(agent.netPolPods.GetPodForObj(npkey)) > 0 {
			return true
		}
	}
	return false
}

// isStaticOrNodeHpp returns true if specName is one of the static policies
// (static-ingress, static-egress, static-discovery) or this node's node policy.
func (agent *HostAgent) isStaticOrNodeHpp(specName string) bool {
	switch specName {
	case util.AciNameForKey(agent.config.AciPrefix, "np", "static-ingress"),
		util.AciNameForKey(agent.config.AciPrefix, "np", "static-egress"),
		util.AciNameForKey(agent.config.AciPrefix, "np", "static-discovery"):
		return true
	}
	return specName == util.AciNameForKey(agent.config.AciPrefix, "node", agent.config.NodeName)
}

// handleHppAdd handles a newly-added HPP: builds the RIC→HPP reverse index
// mapping from scratch (there is no prior state to diff against) and applies
// the HPP (render + eager static write + schedule sync).
func (agent *HostAgent) handleHppAdd(hpp *hppv1.HostprotPol) {
	agent.hppMutex.Lock()
	defer agent.hppMutex.Unlock()

	hppKey := hpp.Namespace + "/" + hpp.Name
	agent.rebuildRicMappingForHpp(nil, hpp, hppKey)
	agent.queueHppIfLocal(hpp)
}

// handleHppUpdate handles an HPP spec update. It diffs the RIC references
// between oldHpp and newHpp so only the RIC→HPP mapping entries that actually
// changed are touched, then applies the new state (render + eager static
// write + schedule sync).
func (agent *HostAgent) handleHppUpdate(oldHpp, newHpp *hppv1.HostprotPol) {
	agent.hppMutex.Lock()
	defer agent.hppMutex.Unlock()

	hppKey := newHpp.Namespace + "/" + newHpp.Name
	agent.rebuildRicMappingForHpp(oldHpp, newHpp, hppKey)
	agent.queueHppIfLocal(newHpp)
}

// queueHppIfLocal gates on node-locality: if relevant, enqueues the HPP key
// on hppQueue for deduplicated async rendering (duplicate keys collapse);
// otherwise evicts any existing render. Caller must hold hppMutex.
func (agent *HostAgent) queueHppIfLocal(hpp *hppv1.HostprotPol) {
	// Node-locality gate: skip rendering if not relevant to this node.
	if !agent.isHppLocallyRelevant(hpp) {
		// If previously local, remove from index (pod may have moved away).
		if _, existed := agent.hppMoIndex[hpp.Spec.Name]; existed {
			delete(agent.hppMoIndex, hpp.Spec.Name)
			agent.scheduleSyncLocalHppMo()
		}
		return
	}
	agent.hppQueue.Add(hpp.Namespace + "/" + hpp.Name)
}

// handleHppQueueItem renders one dequeued HPP. Returns true to request a
// rate-limited requeue (render failed), false when done.
func (agent *HostAgent) handleHppQueueItem(obj interface{}) bool {
	hpp, ok := obj.(*hppv1.HostprotPol)
	if !ok {
		agent.log.Errorf("Invalid item in HPP queue: %v", obj)
		return false
	}
	if !agent.renderHppToIndex(hpp) {
		return true
	}
	// Static and node policies are critical for baseline connectivity (ARP,
	// ICMP, node protection). Write them to disk eagerly — don't wait for
	// the deferred sync queue — so they're available as soon as the
	// informer delivers them during initial cache sync.
	if agent.isStaticOrNodeHpp(hpp.Spec.Name) {
		agent.hppMutex.Lock()
		modb, ok := agent.hppMoIndex[hpp.Spec.Name]
		agent.hppMutex.Unlock()
		if ok {
			if !agent.writeNetpolFileAtomic(modb, hpp.Spec.Name) {
				agent.log.Errorf("Failed to write netpol file for HPP: %s", hpp.Spec.Name)
				return true
			}
		}
	}

	agent.scheduleSyncLocalHppMo()
	return false
}

// handleHppDelete cleans up MO index and the RIC reverse index for a deleted
// HPP. The corresponding netpol file (if any) is removed by the next
// syncLocalHppMo reconcile, same as any other entry that leaves hppMoIndex.
func (agent *HostAgent) handleHppDelete(hpp *hppv1.HostprotPol) {

	hppKey, err := cache.MetaNamespaceKeyFunc(hpp)
	if err != nil {
		agent.log.Errorf("Failed to get HPP key: %v", err)
		return
	}
	specName := hpp.Spec.Name

	agent.hppMutex.Lock()
	_, present := agent.hppMoIndex[specName]
	delete(agent.hppMoIndex, specName)
	agent.removeRicMappingsForHpp(hppKey)
	agent.hppMutex.Unlock()

	if present {
		agent.scheduleSyncLocalHppMo()
	}
}

// rebuildRicMappingForHpp reconciles the ricToHpp reverse index for a given
// HPP by diffing the RIC references in oldHpp against newHpp, so only
// entries that actually changed are touched. oldHpp may be nil (e.g. for a
// newly-added HPP), in which case all of newHpp's RIC references are simply
// added. ricToHpp maps RIC object name → set of HPP k8s keys (namespace/name).
// Caller must hold hppMutex.
func (agent *HostAgent) rebuildRicMappingForHpp(oldHpp, newHpp *hppv1.HostprotPol, hppKey string) {
	oldRics := ricRefsForHpp(oldHpp)
	newRics := ricRefsForHpp(newHpp)

	for ric := range oldRics {
		if newRics[ric] {
			continue
		}
		if hpps, ok := agent.ricToHpp[ric]; ok {
			delete(hpps, hppKey)
			if len(hpps) == 0 {
				delete(agent.ricToHpp, ric)
			}
		}
	}
	for ric := range newRics {
		if agent.ricToHpp[ric] == nil {
			agent.ricToHpp[ric] = make(map[string]bool)
		}
		agent.ricToHpp[ric][hppKey] = true
	}
}

// ricRefsForHpp returns the set of distinct RsRemoteIpContainer names
// referenced by hpp. Returns an empty set if hpp is nil.
func ricRefsForHpp(hpp *hppv1.HostprotPol) map[string]bool {
	refs := make(map[string]bool)
	if hpp == nil {
		return refs
	}
	for _, subj := range hpp.Spec.HostprotSubj {
		for _, rule := range subj.HostprotRule {
			if rule.RsRemoteIpContainer != "" {
				refs[rule.RsRemoteIpContainer] = true
			}
		}
	}
	return refs
}

func (agent *HostAgent) getHPPDirLabelKey(np *v1net.NetworkPolicy) (labelKey string, err error) {
	hash, err := util.CreateCanonicalHashFromNetPol(np)
	if err != nil {
		return "", err
	}
	labelKey = util.AciNameForKey(agent.config.AciPrefix, "np", hash)
	return labelKey, nil
}

// removeRicMappingsForHpp removes all ricToHpp entries for a given HPP k8s key.
// Caller must hold hppMutex.
func (agent *HostAgent) removeRicMappingsForHpp(hppKey string) {
	for ric, hpps := range agent.ricToHpp {
		delete(hpps, hppKey)
		if len(hpps) == 0 {
			delete(agent.ricToHpp, ric)
		}
	}
}

func (agent *HostAgent) evictStaleHppForNp(npkey string) {
	if len(agent.netPolPods.GetPodForObj(npkey)) > 0 {
		return
	}
	obj, exists, err := agent.netPolInformer.GetIndexer().GetByKey(npkey)
	if err != nil || !exists || obj == nil {
		agent.log.Debugf("evictStaleHppForNp: NP %s not found in informer", npkey)
		return
	}
	np, ok := obj.(*v1net.NetworkPolicy)
	if !ok {
		agent.log.Errorf("evictStaleHppForNp: NP %s informer object is not a NetworkPolicy", npkey)
		return
	}
	specName, err := agent.getHPPDirLabelKey(np)
	if err != nil {
		agent.log.Errorf("evictStaleHppForNp: failed to compute HPP label key for NP %s: %v", npkey, err)
		return
	}
	agent.hppMutex.Lock()
	_, present := agent.hppMoIndex[specName]
	if present {
		delete(agent.hppMoIndex, specName)
	}
	agent.hppMutex.Unlock()

	if present {
		agent.scheduleSyncLocalHppMo()
	}
}

// ensureLocalHppsRendered ensures that HPPs corresponding to the given labelKeys
// are rendered into hppMoIndex. Called from the pod path when a pod becomes
// selected by a NP whose HPP might not yet be in the node-local index.
func (agent *HostAgent) ensureLocalHppsRendered(labelKeys []string) {
	ns := agent.config.AciHppObjsNamespace
	agent.hppMutex.Lock()
	defer agent.hppMutex.Unlock()
	for _, labelKey := range labelKeys {
		if _, ok := agent.hppMoIndex[labelKey]; ok {
			continue
		}
		// Look up the HPP object from the informer by its k8s key.
		hppName := strings.ReplaceAll(labelKey, "_", "-")
		hppKey := ns + "/" + hppName
		agent.hppQueue.Add(hppKey)
	}
}

// renderHppToIndex renders hpp into GBP MOs and writes hppMoIndex. Returns
// false if a referenced RIC isn't cached yet (caller should requeue).
//
// Runs only on the single hppQueue worker, so building into the global
// GbpConfig scratch needs no lock; only the final hppMoIndex write takes
// hppMutex, since other goroutines also touch that map.
func (agent *HostAgent) renderHppToIndex(hpp *hppv1.HostprotPol) bool {
	logger := HppLogger(agent.log, hpp)
	ns := agent.config.AciHppObjsNamespace
	agent.initGbpConfig()
	np := &NetworkPolicy{
		HostprotPol: Hpp{
			Attributes: map[string]string{},
			Children:   []map[string]*HpSubj{},
		},
	}

	for _, subj := range hpp.Spec.HostprotSubj {
		hpSubj := &HpSubj{
			Attributes: map[string]string{
				propName: subj.Name,
			},
			Children: []map[string]HpSubjChild{},
		}
		for _, rule := range subj.HostprotRule {
			hpRule := &HpSubjChild{
				Attributes: map[string]string{
					propName:    rule.Name,
					"direction": rule.Direction,
					"protocol":  rule.Protocol,
					"fromPort":  rule.FromPort,
					"toPort":    rule.ToPort,
					"connTrack": rule.ConnTrack,
					"ethertype": rule.Ethertype,
				},
				Children: []map[string]HpSubjGrandchild{},
			}

			if len(rule.HostprotServiceRemoteIps) > 0 {
				for _, remoteIp := range rule.HostprotServiceRemoteIps {
					hpSubnet := &HpSubjGrandchild{
						Attributes: map[string]string{
							"addr": remoteIp,
						},
					}
					hpRule.Children = append(hpRule.Children, map[string]HpSubjGrandchild{"hostprotRemoteIp": *hpSubnet})
				}
			} else {
				if rule.RsRemoteIpContainer != "" {
					remoteIpCont, err := agent.getHostprotRemoteIpContainer(rule.RsRemoteIpContainer, ns)
					if err != nil {
						logger.Error("Error getting HostprotRemoteIpContainer: ", err)
						return false
					}
					for _, ip := range remoteIpCont.Spec.HostprotRemoteIps {
						hpSubnet := &HpSubjGrandchild{
							Attributes: map[string]string{
								"addr": ip,
							},
						}
						hpRule.Children = append(hpRule.Children, map[string]HpSubjGrandchild{"hostprotRemoteIp": *hpSubnet})
					}
				}

				for _, ip := range rule.HostprotRemoteIps {
					hpSubnet := &HpSubjGrandchild{
						Attributes: map[string]string{
							"addr": ip,
						},
					}
					hpRule.Children = append(hpRule.Children, map[string]HpSubjGrandchild{"hostprotRemoteIp": *hpSubnet})
				}
			}

			hpSubj.Children = append(hpSubj.Children, map[string]HpSubjChild{"hostprotRule": *hpRule})
		}
		np.HostprotPol.Children = append(np.HostprotPol.Children, map[string]*HpSubj{"hostprotSubj": hpSubj})
	}

	np.HostprotPol.Attributes[propName] = hpp.Spec.Name

	if err := np.Make(); err != nil {
		agent.log.Errorf("network policy render -- %v", err)
		return false
	}
	modb := getMoDB()
	agent.hppMutex.Lock()
	agent.hppMoIndex[hpp.Spec.Name] = *modb
	agent.hppMutex.Unlock()
	return true
}

// syncLocalHppMo reconciles the netpol file directory against the node-local
// hppMoIndex desired state. Follows the same pattern as syncEps/syncServices/syncSnat:
// read directory, update/delete existing files, add missing files.
func (agent *HostAgent) syncLocalHppMo() bool {
	agent.hppMutex.Lock()
	localMoIndex := make(map[string][]*gbpBaseMo, len(agent.hppMoIndex))
	for k, v := range agent.hppMoIndex {
		localMoIndex[k] = v
	}
	agent.hppMutex.Unlock()

	dir := agent.config.OpFlexNetPolDir
	if dir == "" {
		return false
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		agent.log.WithFields(logrus.Fields{
			"netpolDir": dir,
		}).Error("Could not read directory: ", err)
		return true
	}

	seen := make(map[string]bool)
	for _, f := range files {
		name := f.Name()
		if strings.Contains(name, ".netpol.tmp") {
			// Unique tmp file from writeNetpolFileAtomic's CreateTemp+Rename.
			// Only remove if its mtime predates this process's start —
			// guarantees we never delete an in-flight write from ourselves.
			info, err := f.Info()
			if err == nil && info.ModTime().Before(hostAgentStartTime) {
				filePath := filepath.Join(dir, name)
				agent.log.Warnf("Removing stale tmp netpol file %s", name)
				os.Remove(filePath)
			}
			continue
		}
		if !strings.HasSuffix(name, ".netpol") {
			continue
		}
		labelKey := strings.TrimSuffix(name, ".netpol")

		if modb, ok := localMoIndex[labelKey]; ok {
			// File exists and HPP is in desired state — write/update.
			if !agent.writeNetpolFileAtomic(modb, labelKey) {
				agent.log.Errorf("Error writing netpol file: %s", labelKey)
				return true
			}
			seen[labelKey] = true
		} else {
			// File exists but HPP not in local desired state. Defer this prune
			// until the initial render batch has drained (hppSyncEnabled); a
			// partially-populated index at startup must not delete files that
			// are about to be re-rendered.
			if !agent.hppSyncEnabled.Load() {
				continue
			}
			filePath := filepath.Join(dir, name)
			agent.log.Infof("Removing netpol file %s", name)
			os.Remove(filePath)
		}
	}

	// Add files for HPPs in desired state not yet on disk.
	for labelKey, modb := range localMoIndex {
		if seen[labelKey] {
			continue
		}
		agent.log.Infof("Adding netpol file %s", labelKey)
		if !agent.writeNetpolFileAtomic(modb, labelKey) {
			agent.log.Errorf("Error writing netpol file: %s", labelKey)
			return true
		}
	}

	agent.log.Debug("Finished netpol sync")
	return false
}

// writeNetpolFileAtomic writes the netpol JSON via a uniquely-named tmp file
// then renames it into place atomically. Each call gets its own tmp file
// (via os.CreateTemp), so concurrent writers targeting the same labelKey can
// never collide on the tmp path — the final os.Rename is atomic and whichever
// completes last simply wins.
// Returns true if the file was written or already up-to-date, false on failure.
func (agent *HostAgent) writeNetpolFileAtomic(modb []*gbpBaseMo, labelKey string) bool {
	policyDBJson, err := json.MarshalIndent(modb, "", "  ")
	if err != nil {
		agent.log.Errorf("Failed to marshal policyDB for %s: %v", labelKey, err)
		return false
	}
	dir := agent.config.OpFlexNetPolDir
	filePath := filepath.Join(dir, fmt.Sprintf("%s.netpol", labelKey))

	// Check if content is unchanged — skip write if identical.
	existingContent, err := os.ReadFile(filePath)
	if err == nil && string(existingContent) == string(policyDBJson) {
		NetpolFileSkips.Add(1)
		return true
	} else if err != nil && !os.IsNotExist(err) {
		agent.log.Errorf("Failed to read existing netpol file %s: %v", filePath, err)
		return false
	} else if os.IsNotExist(err) {
		agent.log.Debugf("J: Netpol file %s does not exist, will create", filePath)
	}
	// Test scaffolding: the on-disk file exists but its content differs from the
	// freshly-rendered JSON. Log a per-line diff (on-disk -> rendered) so we can
	// tell whether the render is non-deterministic (e.g. map/slice ordering
	// churn) versus a genuine spec change — remove after testing.
	if err == nil {
		diff := cmp.Diff(
			strings.Split(string(existingContent), "\n"),
			strings.Split(string(policyDBJson), "\n"))
		agent.log.Infof("netpol file %s content differs (on-disk -> rendered):\n%s", labelKey, diff)
	}

	// Atomic write: create a unique tmp file, write, chmod, rename.
	tmpFile, err := os.CreateTemp(dir, labelKey+".netpol.tmp*")
	if err != nil {
		agent.log.Errorf("Failed to create tmp netpol file for %s: %v", labelKey, err)
		return false
	}
	tmpPath := tmpFile.Name()
	_, writeErr := tmpFile.Write(policyDBJson)
	closeErr := tmpFile.Close()
	if writeErr != nil || closeErr != nil {
		agent.log.Errorf("Failed to write tmp netpol file %s: write=%v close=%v", tmpPath, writeErr, closeErr)
		os.Remove(tmpPath)
		return false
	}
	// CreateTemp uses mode 0600; match the rest of the codebase (0644).
	if err := os.Chmod(tmpPath, 0644); err != nil {
		agent.log.Errorf("Failed to chmod tmp netpol file %s: %v", tmpPath, err)
		os.Remove(tmpPath)
		return false
	}
	if err := os.Rename(tmpPath, filePath); err != nil {
		agent.log.Errorf("Failed to rename tmp netpol file %s -> %s: %v", tmpPath, filePath, err)
		os.Remove(tmpPath)
		return false
	}
	NetpolFileWrites.Add(1)
	agent.log.Infof("HPP %s updated", labelKey)
	return true
}

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	fabatt "github.com/noironetworks/aci-containers/pkg/fabricattachment/apis/aci.fabricattachment"
)

// SchemeGroupVersion is group version used to register these objects
var SchemeGroupVersion = schema.GroupVersion{Group: fabatt.GroupName, Version: "v1"}

// Resource takes an unqualified resource and returns a Group qualified
// GroupResource
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

var (
	// localSchemeBuilder and AddToScheme will stay in k8s.io/kubernetes.
	SchemeBuilder      runtime.SchemeBuilder
	localSchemeBuilder = &SchemeBuilder
	AddToScheme        = localSchemeBuilder.AddToScheme
)

func init() {
	// We only register manually written functions here. The registration of the
	// generated functions takes place in the generated files. The separation
	// makes the code compile even when the generated files are missing.
	localSchemeBuilder.Register(addKnownTypes)
}

// Adds the list of known types to api.Scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&NodeFabricNetworkAttachment{}, &NodeFabricNetworkAttachmentList{},
	)
	scheme.AddKnownTypes(SchemeGroupVersion,
		&NadVlanMap{}, &NadVlanMapList{},
	)
	scheme.AddKnownTypes(SchemeGroupVersion,
		&NetworkFabricConfiguration{}, &NetworkFabricConfigurationList{},
	)
	scheme.AddKnownTypes(SchemeGroupVersion,
		&FabricVlanPool{}, &FabricVlanPoolList{},
	)
	scheme.AddKnownTypes(SchemeGroupVersion,
		&NetworkFabricL3Configuration{}, &NetworkFabricL3ConfigurationList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

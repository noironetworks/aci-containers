package controller

type AciFault struct {
  Cause string `json:"cause,omitempty"`
  Description string `json:"description,omitempty"`
  ExternalIdentifier string `json:"external_identifier"`
  FaultCode string `json:"fault_code"`
  LastUpdateTimestamp string `json:"last_update_timestamp,omitempty"`
  Severity string `json:"severity,omitempty"`
  StatusId string `json:"status_id,omitempty"`
}

type AciObjectSpec struct {
  AciFault *AciFault `json:"aci_fault,omitempty"`
  AciStatus *AciStatus `json:"aci_status,omitempty"`
  Agent *Agent `json:"agent,omitempty"`
  ApplicationProfile *ApplicationProfile `json:"application_profile,omitempty"`
  BridgeDomain *BridgeDomain `json:"bridge_domain,omitempty"`
  Configuration *Configuration `json:"configuration,omitempty"`
  Contract *Contract `json:"contract,omitempty"`
  ContractSubject *ContractSubject `json:"contract_subject,omitempty"`
  DeviceCluster *DeviceCluster `json:"device_cluster,omitempty"`
  DeviceClusterContext *DeviceClusterContext `json:"device_cluster_context,omitempty"`
  Endpoint *Endpoint `json:"endpoint,omitempty"`
  EndpointGroup *EndpointGroup `json:"endpoint_group,omitempty"`
  ExternalNetwork *ExternalNetwork `json:"external_network,omitempty"`
  ExternalSubnet *ExternalSubnet `json:"external_subnet,omitempty"`
  Filter *Filter `json:"filter,omitempty"`
  FilterEntry *FilterEntry `json:"filter_entry,omitempty"`
  HostLink *HostLink `json:"host_link,omitempty"`
  L3Outside *L3Outside `json:"l3_outside,omitempty"`
  PhysicalDomain *PhysicalDomain `json:"physical_domain,omitempty"`
  SecurityGroup *SecurityGroup `json:"security_group,omitempty"`
  SecurityGroupRule *SecurityGroupRule `json:"security_group_rule,omitempty"`
  SecurityGroupSubject *SecurityGroupSubject `json:"security_group_subject,omitempty"`
  ServiceGraph *ServiceGraph `json:"service_graph,omitempty"`
  ServiceRedirectPolicy *ServiceRedirectPolicy `json:"service_redirect_policy,omitempty"`
  Subnet *Subnet `json:"subnet,omitempty"`
  Tenant *Tenant `json:"tenant,omitempty"`
  Type string `json:"type,omitempty"`
  VmmDomain *VmmDomain `json:"vmm_domain,omitempty"`
  Vrf *Vrf `json:"vrf,omitempty"`
}

type AciStatus struct {
  Faults []string `json:"faults,omitempty"`
  HealthScore float64 `json:"health_score,omitempty"`
  Id string `json:"id,omitempty"`
  ResourceId string `json:"resource_id"`
  ResourceType string `json:"resource_type"`
  SyncMessage string `json:"sync_message,omitempty"`
  SyncStatus string `json:"sync_status,omitempty"`
}

type Agent struct {
  AdminStateUp *bool `json:"admin_state_up,omitempty"`
  AgentType string `json:"agent_type,omitempty"`
  BeatCount float64 `json:"beat_count,omitempty"`
  BinaryFile string `json:"binary_file,omitempty"`
  Description string `json:"description,omitempty"`
  HashTrees []string `json:"hash_trees,omitempty"`
  HeartbeatTimestamp string `json:"heartbeat_timestamp,omitempty"`
  Host string `json:"host,omitempty"`
  Id string `json:"id"`
  Version string `json:"version,omitempty"`
}

type ApplicationProfile struct {
  DisplayName string `json:"display_name,omitempty"`
  Monitored *bool `json:"monitored,omitempty"`
  Name string `json:"name"`
  TenantName string `json:"tenant_name"`
}

type BridgeDomain struct {
  DisplayName string `json:"display_name,omitempty"`
  EnableArpFlood *bool `json:"enable_arp_flood,omitempty"`
  EnableRouting *bool `json:"enable_routing,omitempty"`
  EpMoveDetectMode string `json:"ep_move_detect_mode,omitempty"`
  L2UnknownUnicastMode string `json:"l2_unknown_unicast_mode,omitempty"`
  L3outNames []string `json:"l3out_names,omitempty"`
  LimitIpLearnToSubnets *bool `json:"limit_ip_learn_to_subnets,omitempty"`
  Monitored *bool `json:"monitored,omitempty"`
  Name string `json:"name"`
  TenantName string `json:"tenant_name"`
  VrfName string `json:"vrf_name,omitempty"`
}

type Configuration struct {
  Group string `json:"group"`
  Host string `json:"host"`
  Key string `json:"key"`
  Value string `json:"value,omitempty"`
  Version string `json:"version,omitempty"`
}

type Contract struct {
  DisplayName string `json:"display_name,omitempty"`
  Monitored *bool `json:"monitored,omitempty"`
  Name string `json:"name"`
  Scope string `json:"scope,omitempty"`
  TenantName string `json:"tenant_name"`
}

type ContractSubject struct {
  BiFilters []string `json:"bi_filters,omitempty"`
  ContractName string `json:"contract_name"`
  DisplayName string `json:"display_name,omitempty"`
  InFilters []string `json:"in_filters,omitempty"`
  Monitored *bool `json:"monitored,omitempty"`
  Name string `json:"name"`
  OutFilters []string `json:"out_filters,omitempty"`
  ServiceGraphName string `json:"service_graph_name,omitempty"`
  TenantName string `json:"tenant_name"`
}

type Destinations struct {
  Ip string `json:"ip,omitempty"`
  Mac string `json:"mac,omitempty"`
}

type DeviceCluster struct {
  ContextAware string `json:"context_aware,omitempty"`
  DeviceType string `json:"device_type,omitempty"`
  Devices []Devices `json:"devices,omitempty"`
  DisplayName string `json:"display_name,omitempty"`
  Encap string `json:"encap,omitempty"`
  Managed *bool `json:"managed,omitempty"`
  Monitored *bool `json:"monitored,omitempty"`
  Name string `json:"name"`
  PhysicalDomainName string `json:"physical_domain_name,omitempty"`
  ServiceType string `json:"service_type,omitempty"`
  TenantName string `json:"tenant_name"`
}

type DeviceClusterContext struct {
  BridgeDomainName string `json:"bridge_domain_name,omitempty"`
  BridgeDomainTenantName string `json:"bridge_domain_tenant_name,omitempty"`
  ContractName string `json:"contract_name"`
  DeviceClusterName string `json:"device_cluster_name,omitempty"`
  DeviceClusterTenantName string `json:"device_cluster_tenant_name,omitempty"`
  DisplayName string `json:"display_name,omitempty"`
  Monitored *bool `json:"monitored,omitempty"`
  NodeName string `json:"node_name"`
  ServiceGraphName string `json:"service_graph_name"`
  ServiceRedirectPolicyName string `json:"service_redirect_policy_name,omitempty"`
  ServiceRedirectPolicyTenantName string `json:"service_redirect_policy_tenant_name,omitempty"`
  TenantName string `json:"tenant_name"`
}

type Devices struct {
  Name string `json:"name,omitempty"`
  Path string `json:"path,omitempty"`
}

type Endpoint struct {
  DisplayName string `json:"display_name,omitempty"`
  EpgAppProfileName string `json:"epg_app_profile_name,omitempty"`
  EpgName string `json:"epg_name,omitempty"`
  EpgTenantName string `json:"epg_tenant_name,omitempty"`
  Uuid string `json:"uuid"`
}

type EndpointGroup struct {
  AppProfileName string `json:"app_profile_name"`
  BdName string `json:"bd_name,omitempty"`
  ConsumedContractNames []string `json:"consumed_contract_names,omitempty"`
  DisplayName string `json:"display_name,omitempty"`
  Monitored *bool `json:"monitored,omitempty"`
  Name string `json:"name"`
  OpenstackVmmDomainNames []string `json:"openstack_vmm_domain_names,omitempty"`
  PhysicalDomainNames []string `json:"physical_domain_names,omitempty"`
  PolicyEnforcementPref string `json:"policy_enforcement_pref,omitempty"`
  ProvidedContractNames []string `json:"provided_contract_names,omitempty"`
  StaticPaths []StaticPaths `json:"static_paths,omitempty"`
  TenantName string `json:"tenant_name"`
}

type ExternalNetwork struct {
  ConsumedContractNames []string `json:"consumed_contract_names,omitempty"`
  DisplayName string `json:"display_name,omitempty"`
  L3outName string `json:"l3out_name"`
  Monitored *bool `json:"monitored,omitempty"`
  Name string `json:"name"`
  NatEpgDn string `json:"nat_epg_dn,omitempty"`
  ProvidedContractNames []string `json:"provided_contract_names,omitempty"`
  TenantName string `json:"tenant_name"`
}

type ExternalSubnet struct {
  Cidr string `json:"cidr"`
  DisplayName string `json:"display_name,omitempty"`
  ExternalNetworkName string `json:"external_network_name"`
  L3outName string `json:"l3out_name"`
  Monitored *bool `json:"monitored,omitempty"`
  TenantName string `json:"tenant_name"`
}

type Filter struct {
  DisplayName string `json:"display_name,omitempty"`
  Monitored *bool `json:"monitored,omitempty"`
  Name string `json:"name"`
  TenantName string `json:"tenant_name"`
}

type FilterEntry struct {
  ArpOpcode string `json:"arp_opcode,omitempty"`
  DestFromPort string `json:"dest_from_port,omitempty"`
  DestToPort string `json:"dest_to_port,omitempty"`
  DisplayName string `json:"display_name,omitempty"`
  EtherType string `json:"ether_type,omitempty"`
  FilterName string `json:"filter_name"`
  FragmentOnly *bool `json:"fragment_only,omitempty"`
  Icmpv4Type string `json:"icmpv4_type,omitempty"`
  Icmpv6Type string `json:"icmpv6_type,omitempty"`
  IpProtocol string `json:"ip_protocol,omitempty"`
  Monitored *bool `json:"monitored,omitempty"`
  Name string `json:"name"`
  SourceFromPort string `json:"source_from_port,omitempty"`
  SourceToPort string `json:"source_to_port,omitempty"`
  Stateful *bool `json:"stateful,omitempty"`
  TcpFlags string `json:"tcp_flags,omitempty"`
  TenantName string `json:"tenant_name"`
}

type HostLink struct {
  HostName string `json:"host_name"`
  InterfaceMac string `json:"interface_mac,omitempty"`
  InterfaceName string `json:"interface_name"`
  Module string `json:"module,omitempty"`
  Path string `json:"path,omitempty"`
  Port string `json:"port,omitempty"`
  SwitchId string `json:"switch_id,omitempty"`
}

type L3Outside struct {
  DisplayName string `json:"display_name,omitempty"`
  L3DomainDn string `json:"l3_domain_dn,omitempty"`
  Monitored *bool `json:"monitored,omitempty"`
  Name string `json:"name"`
  TenantName string `json:"tenant_name"`
  VrfName string `json:"vrf_name,omitempty"`
}

type LinearChainNodes struct {
  DeviceClusterName string `json:"device_cluster_name,omitempty"`
  DeviceClusterTenantName string `json:"device_cluster_tenant_name,omitempty"`
  Name string `json:"name,omitempty"`
}

type PhysicalDomain struct {
  Name string `json:"name"`
}

type SecurityGroup struct {
  DisplayName string `json:"display_name,omitempty"`
  Monitored *bool `json:"monitored,omitempty"`
  Name string `json:"name"`
  TenantName string `json:"tenant_name"`
}

type SecurityGroupRule struct {
  ConnTrack string `json:"conn_track,omitempty"`
  Direction string `json:"direction,omitempty"`
  DisplayName string `json:"display_name,omitempty"`
  Ethertype string `json:"ethertype,omitempty"`
  FromPort string `json:"from_port,omitempty"`
  IpProtocol string `json:"ip_protocol,omitempty"`
  Monitored *bool `json:"monitored,omitempty"`
  Name string `json:"name"`
  RemoteIps []string `json:"remote_ips,omitempty"`
  SecurityGroupName string `json:"security_group_name"`
  SecurityGroupSubjectName string `json:"security_group_subject_name"`
  TenantName string `json:"tenant_name"`
  ToPort string `json:"to_port,omitempty"`
}

type SecurityGroupSubject struct {
  DisplayName string `json:"display_name,omitempty"`
  Monitored *bool `json:"monitored,omitempty"`
  Name string `json:"name"`
  SecurityGroupName string `json:"security_group_name"`
  TenantName string `json:"tenant_name"`
}

type ServiceGraph struct {
  DisplayName string `json:"display_name,omitempty"`
  LinearChainNodes []LinearChainNodes `json:"linear_chain_nodes,omitempty"`
  Monitored *bool `json:"monitored,omitempty"`
  Name string `json:"name"`
  TenantName string `json:"tenant_name"`
}

type ServiceRedirectPolicy struct {
  Destinations []Destinations `json:"destinations,omitempty"`
  DisplayName string `json:"display_name,omitempty"`
  Monitored *bool `json:"monitored,omitempty"`
  Name string `json:"name"`
  TenantName string `json:"tenant_name"`
}

type StaticPaths struct {
  Encap string `json:"encap,omitempty"`
}

type Subnet struct {
  BdName string `json:"bd_name"`
  DisplayName string `json:"display_name,omitempty"`
  GwIpMask string `json:"gw_ip_mask"`
  Monitored *bool `json:"monitored,omitempty"`
  Scope string `json:"scope,omitempty"`
  TenantName string `json:"tenant_name"`
}

type Tenant struct {
  DisplayName string `json:"display_name,omitempty"`
  Monitored *bool `json:"monitored,omitempty"`
  Name string `json:"name"`
}

type VmmDomain struct {
  Name string `json:"name"`
  Type string `json:"type"`
}

type Vrf struct {
  DisplayName string `json:"display_name,omitempty"`
  Monitored *bool `json:"monitored,omitempty"`
  Name string `json:"name"`
  PolicyEnforcementPref string `json:"policy_enforcement_pref,omitempty"`
  TenantName string `json:"tenant_name"`
}

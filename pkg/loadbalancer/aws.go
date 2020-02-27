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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package loadbalancer

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elbv2"
	v1 "k8s.io/api/core/v1"
	"sync"
)

var (
	defaultLB = "opflex-CNI-LB"
	nwLB      = "network"
)

type AwsLB struct {
	sync.Mutex
	vpcID     string
	client    *elbv2.ELBV2
	elbList   []*elbv2.CreateLoadBalancerOutput
	services  map[string]*svcInfo
	ec2Client *ec2.EC2
	ipToInst  map[string]string
}

type svcInfo struct {
	// kubernetes service
	svc *v1.Service
	// elb listener info for this service
	elbListeners []*elbv2.Listener
	// nodePort on kube nodes for this service
	nodePort int
	//elb target groups
	targetGroupARN *string
	// nodes that have pods serving this service
	targets []string
}

func NewAwsLB() *AwsLB {
	sess := session.New()
	return &AwsLB{
		client:    elbv2.New(sess),
		services:  make(map[string]*svcInfo),
		ec2Client: ec2.New(sess),
		ipToInst:  make(map[string]string),
	}
}

func (a *AwsLB) Init(vpc string, subnets []string) error {

	a.vpcID = vpc
	netList := make([]*string, len(subnets))
	for ix := range subnets {
		netList[ix] = &subnets[ix]
	}

	input := &elbv2.CreateLoadBalancerInput{
		Name:    &defaultLB,
		Subnets: netList,
		Type:    &nwLB,
	}

	log.Infof("subnets: %+v", subnets)

	result, err := a.client.CreateLoadBalancer(input)
	if err != nil {
		return err
	}

	log.Infof("Result: %+v", result)

	a.elbList = append(a.elbList, result)
	return nil

}

func (a *AwsLB) UpdateService(s *v1.Service, nodeIPs []string) error {
	a.Lock()
	defer a.Unlock()

	sKey := getSvcKey(s)
	log.Infof("UpdateService: %s, %+v", sKey, nodeIPs)
	var err error
	if s.Spec.Type != "LoadBalancer" {
		log.Infof("Ignore service %s type: %s", s.ObjectMeta.Name, s.Spec.Type)
		return nil
	}

	_, ok := a.services[sKey]
	if !ok {
		err = a.createNewService(s)
	} else {
		//err = a.modifyListener(s)
	}

	if err != nil {
		return err
	}

	return a.updateTargetGroup(sKey, nodeIPs)
}

func (a *AwsLB) createNewService(s *v1.Service) error {
	sKey := getSvcKey(s)
	si := &svcInfo{svc: s}
	// create a target group
	tg_input := &elbv2.CreateTargetGroupInput{
		Name: aws.String(sKey),
		//HealthCheckEnabled: aws.Bool(false),
		Port:     aws.Int64(int64(s.Spec.Ports[0].NodePort)),
		Protocol: aws.String("TCP"),
		VpcId:    aws.String(a.vpcID),
		//TargetType:         aws.String("ip"),
		HealthCheckPath:     aws.String("/status"),
		HealthCheckPort:     aws.String("8090"),
		HealthCheckProtocol: aws.String("HTTP"),
	}

	tg_result, err := a.client.CreateTargetGroup(tg_input)
	if err != nil {
		return err
	}

	si.targetGroupARN = tg_result.TargetGroups[0].TargetGroupArn

	tp := &s.Spec.Ports[0].TargetPort
	input := &elbv2.CreateListenerInput{
		DefaultActions: []*elbv2.Action{
			{
				TargetGroupArn: si.targetGroupARN,
				Type:           aws.String("forward"),
			},
		},
		LoadBalancerArn: a.elbList[0].LoadBalancers[0].LoadBalancerArn,
		Port:            aws.Int64(int64(tp.IntValue())),
		Protocol:        aws.String("TCP"),
	}

	result, err := a.client.CreateListener(input)
	if err != nil {
		return err
	}

	log.Infof("LB listeners: %+v", result.Listeners)
	si.elbListeners = result.Listeners
	a.services[sKey] = si
	return nil
}

func (a *AwsLB) updateTargetGroup(sKey string, targets []string) error {
	si := a.services[sKey]
	if si == nil {
		return fmt.Errorf("updateTargetGroup: service %s not found!", sKey)
	}

	targets = a.ipToInstance(targets)
	regList, deregList := targetsDiff(si.targets, targets)
	if len(deregList) > 0 {
		_, err := a.client.DeregisterTargets(&elbv2.DeregisterTargetsInput{
			TargetGroupArn: si.targetGroupARN, Targets: deregList})
		if err != nil {
			return err
		}
	}
	if len(regList) > 0 {
		_, err := a.client.RegisterTargets(&elbv2.RegisterTargetsInput{
			TargetGroupArn: si.targetGroupARN, Targets: regList})
		if err != nil {
			return err
		}
	}

	si.targets = targets

	return nil
}

func (a *AwsLB) ipToInstance(ips []string) []string {
	var res []string
	for _, ip := range ips {
		_, ok := a.ipToInst[ip]
		if !ok {
			a.fetchInstance(ip)
		}
		res = append(res, a.ipToInst[ip])
	}

	log.Infof("ipToInstance ip: %+v, instances: %+v", ips, res)
	return res
}

func (a *AwsLB) fetchInstance(ip string) {
	ec2_input := &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("private-ip-address"),
				Values: []*string{
					aws.String(ip),
				},
			},
		},
	}
	ec2_res, err := a.ec2Client.DescribeInstances(ec2_input)
	if err != nil {
		log.Infof("DescribeInstances err - %v", err)
	} else {
		for _, rsv := range ec2_res.Reservations {
			for _, inst := range rsv.Instances {
				if inst.InstanceId != nil {
					a.ipToInst[ip] = *inst.InstanceId
					return
				}
			}
		}
	}
}

func getSvcKey(s *v1.Service) string {
	return fmt.Sprintf("%s-%s", s.ObjectMeta.Namespace, s.ObjectMeta.Name)
}

func targetsDiff(old, new []string) ([]*elbv2.TargetDescription, []*elbv2.TargetDescription) {
	// new - old
	r := make(map[string]bool)

	for _, o := range old {
		r[o] = false
	}

	for _, n := range new {
		if _, found := r[n]; found {
			delete(r, n)
		} else {
			r[n] = true
		}
	}

	var add, del []*elbv2.TargetDescription
	for k, v := range r {
		kd := &elbv2.TargetDescription{Id: aws.String(k)}
		if v {
			add = append(add, kd)
		} else {
			del = append(del, kd)
		}
	}

	return add, del
}

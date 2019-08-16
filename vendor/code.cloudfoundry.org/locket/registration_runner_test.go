package locket_test

import (
	"errors"
	"fmt"
	"os"
	"time"

	"code.cloudfoundry.org/clock/fakeclock"
	"code.cloudfoundry.org/consuladapter"
	"code.cloudfoundry.org/consuladapter/fakes"
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/lager/lagertest"
	"code.cloudfoundry.org/locket"
	"github.com/hashicorp/consul/api"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Service Registration Integration", func() {
	const (
		serviceID   = "test-id"
		serviceName = "Test-Service"
	)

	var (
		consulClient consuladapter.Client
		logger       lager.Logger
		clock        *fakeclock.FakeClock

		registration        *api.AgentServiceRegistration
		registrationProcess ifrit.Process
	)

	BeforeEach(func() {
		consulClient = consulRunner.NewClient()

		logger = lagertest.NewTestLogger("test")
		clock = fakeclock.NewFakeClock(time.Now())
		registration = &api.AgentServiceRegistration{
			ID:      serviceID,
			Name:    serviceName,
			Tags:    []string{"a", "b", "c"},
			Port:    8080,
			Address: "127.0.0.1",
		}
	})

	JustBeforeEach(func() {
		registrationRunner := locket.NewRegistrationRunner(logger, registration, consulClient, 5*time.Second, clock)
		registrationProcess = ginkgomon.Invoke(registrationRunner)
	})

	AfterEach(func() {
		ginkgomon.Kill(registrationProcess)
	})

	Context("when the service has not already been registered", func() {
		It("registers the service", func() {
			services, err := consulClient.Agent().Services()
			Expect(err).NotTo(HaveOccurred())
			service, ok := services[registration.ID]
			Expect(ok).To(BeTrue())
			Expect(*service).To(Equal(api.AgentService{
				ID:      registration.ID,
				Service: registration.Name,
				Tags:    registration.Tags,
				Port:    registration.Port,
				Address: registration.Address,
			}))
		})

		Context("when using a TTL check", func() {
			BeforeEach(func() {
				registration.Check = &api.AgentServiceCheck{
					TTL: "10s",
				}
			})

			It("registers the service", func() {
				services, err := consulClient.Agent().Services()
				Expect(err).NotTo(HaveOccurred())
				service, ok := services[registration.ID]
				Expect(ok).To(BeTrue())
				Expect(*service).To(Equal(api.AgentService{
					ID:      registration.ID,
					Service: registration.Name,
					Tags:    registration.Tags,
					Port:    registration.Port,
					Address: registration.Address,
				}))
			})

			It("registers the check", func() {
				checks, err := consulClient.Agent().Checks()
				Expect(err).NotTo(HaveOccurred())
				checkID := "service:" + serviceID
				Expect(checks).To(HaveKeyWithValue(checkID,
					&api.AgentCheck{
						Node:        "0",
						CheckID:     checkID,
						Name:        "Service '" + serviceName + "' check",
						Status:      "passing",
						Notes:       "",
						Output:      "",
						ServiceID:   serviceID,
						ServiceName: serviceName,
					}))
			})

			Context("when the service does not have an ID", func() {
				BeforeEach(func() {
					registration.ID = ""
				})

				It("registers the check using the service name in the check id", func() {
					checks, err := consulClient.Agent().Checks()
					Expect(err).NotTo(HaveOccurred())
					checkID := "service:" + serviceName
					Expect(checks).To(HaveKeyWithValue(checkID,
						&api.AgentCheck{
							Node:        "0",
							CheckID:     checkID,
							Name:        "Service '" + serviceName + "' check",
							Status:      "passing",
							Notes:       "",
							Output:      "",
							ServiceID:   serviceName,
							ServiceName: serviceName,
						}))
				})
			})
		})
	})

	Context("when the service has already been registered", func() {
		BeforeEach(func() {
			oldregistration := *registration
			oldregistration.Port = 9000
			err := consulClient.Agent().ServiceRegister(&oldregistration)
			Expect(err).NotTo(HaveOccurred())
		})

		It("does not exit", func() {
			Consistently(registrationProcess.Wait()).ShouldNot(Receive())
		})

		It("updates the service", func() {
			services, err := consulClient.Agent().Services()
			Expect(err).NotTo(HaveOccurred())
			service, ok := services[registration.ID]
			Expect(ok).To(BeTrue())
			Expect(*service).To(Equal(api.AgentService{
				ID:      registration.ID,
				Service: registration.Name,
				Tags:    registration.Tags,
				Port:    registration.Port,
				Address: registration.Address,
			}))
		})
	})

	Context("when signalled", func() {
		It("deregisters the given service before exiting", func() {
			ginkgomon.Interrupt(registrationProcess)
			services, err := consulClient.Agent().Services()
			Expect(err).NotTo(HaveOccurred())
			Expect(services).ToNot(HaveKey(registration.ID))
		})
	})
})

var _ = Describe("Service Registration Unit Tests", func() {
	var (
		client *fakes.FakeClient
		agent  *fakes.FakeAgent
		logger lager.Logger
		clock  *fakeclock.FakeClock

		registration        *api.AgentServiceRegistration
		registrationRunner  ifrit.Runner
		registrationProcess ifrit.Process
	)

	BeforeEach(func() {
		var fakeComponents *fakes.FakeClientComponents
		client, fakeComponents = fakes.NewFakeClient()
		agent = fakeComponents.Agent
		logger = lagertest.NewTestLogger("test")
		clock = fakeclock.NewFakeClock(time.Now())

		registration = &api.AgentServiceRegistration{
			ID:      "test-id",
			Name:    "Test-Service",
			Tags:    []string{"a", "b", "c"},
			Port:    8080,
			Address: "127.0.0.1",
		}
	})

	JustBeforeEach(func() {
		registrationRunner = locket.NewRegistrationRunner(logger, registration, client, 5*time.Second, clock)
	})

	Context("when the service is invalid", func() {
		JustBeforeEach(func() {
			registrationProcess = ifrit.Background(registrationRunner)
		})

		Context("when the service has a value in the Checks list", func() {
			BeforeEach(func() {
				registration.Checks = []*api.AgentServiceCheck{
					&api.AgentServiceCheck{
						TTL: "1m",
					},
				}
			})

			It("returns a validation error", func() {
				Eventually(registrationProcess.Wait()).Should(Receive(MatchError("Support for multiple service checks not implemented")))
			})

			It("does not become ready", func() {
				Consistently(registrationProcess.Ready()).Should(Not(BeClosed()))
			})

			It("does not try to register the service", func() {
				Consistently(agent.ServiceRegisterCallCount).Should(Equal(0))
			})

			It("does not try to deregister the service", func() {
				Consistently(agent.ServiceDeregisterCallCount).Should(Equal(0))
			})
		})

		Context("when the ttl is not a valid duration", func() {
			BeforeEach(func() {
				registration.Check = &api.AgentServiceCheck{
					TTL: "a minute or so",
				}
			})

			It("returns a validation error", func() {
				Eventually(registrationProcess.Wait()).Should(Receive(MatchError("time: invalid duration a minute or so")))
			})

			It("does not become ready", func() {
				Consistently(registrationProcess.Ready()).Should(Not(BeClosed()))
			})

			It("does not try to register the service", func() {
				Consistently(agent.ServiceRegisterCallCount).Should(Equal(0))
			})

			It("does not try to deregister the service", func() {
				Consistently(agent.ServiceDeregisterCallCount).Should(Equal(0))
			})
		})
	})

	Context("when we register a TTL healthcheck", func() {
		BeforeEach(func() {
			registration.Check = &api.AgentServiceCheck{
				TTL: "10s",
			}
		})

		AfterEach(func() {
			ginkgomon.Kill(registrationProcess)
		})

		JustBeforeEach(func() {
			registrationProcess = ifrit.Invoke(registrationRunner)
		})

		It("should become ready", func() {
			Eventually(registrationProcess.Ready()).Should(BeClosed())
		})

		It("updates the health status after TTL/2", func() {
			Eventually(agent.PassTTLCallCount).Should(Equal(1))
			clock.WaitForWatcherAndIncrement(5 * time.Second)
			Eventually(agent.PassTTLCallCount).Should(Equal(2))
		})

		It("when the passTTL fails we should try and reregister", func() {
			Eventually(agent.ServiceRegisterCallCount()).Should(Equal(1))
			Eventually(agent.PassTTLCallCount).Should(Equal(1))
			agent.PassTTLReturns(fmt.Errorf("Invalid status: failed"))
			clock.WaitForWatcherAndIncrement(5 * time.Second)
			Eventually(agent.PassTTLCallCount).Should(Equal(2))
			Eventually(agent.ServiceRegisterCallCount).Should(Equal(2))
		})

		Context("deregistering the service", func() {
			It("deregisters the service after being signalled", func() {
				Expect(agent.ServiceDeregisterCallCount()).Should(Equal(0))
				ginkgomon.Kill(registrationProcess)
				Expect(agent.ServiceDeregisterCallCount()).Should(Equal(1))
				Expect(agent.ServiceDeregisterArgsForCall(0)).To(Equal(registration.ID))
			})

			Context("when the registration does not have an ID", func() {
				BeforeEach(func() {
					registration.ID = ""
				})

				It("unregisters with the service name", func() {
					Expect(agent.ServiceDeregisterCallCount()).Should(Equal(0))
					ginkgomon.Kill(registrationProcess)
					Expect(agent.ServiceDeregisterCallCount()).Should(Equal(1))
					Expect(agent.ServiceDeregisterArgsForCall(0)).To(Equal(registration.Name))
				})
			})
		})
	})

	Context("when we fail to register the service", func() {
		var registrationError = errors.New("boom")
		BeforeEach(func() {
			agent.ServiceRegisterReturns(registrationError)
		})

		JustBeforeEach(func() {
			registrationProcess = ifrit.Background(registrationRunner)
		})

		AfterEach(func() {
			ginkgomon.Kill(registrationProcess)
		})

		It("retries", func() {
			Eventually(agent.ServiceRegisterCallCount).Should(Equal(1))
			clock.IncrementBySeconds(6)
			Eventually(agent.ServiceRegisterCallCount).Should(Equal(2))
		})

		It("does not become ready", func() {
			Consistently(registrationProcess.Ready()).ShouldNot(BeClosed())
		})
	})

	Context("when registering hangs forever", func() {
		var blockRegister chan struct{}
		var blockRegisterDone chan struct{}

		BeforeEach(func() {
			blockRegister = make(chan struct{})
			blockRegisterDone = make(chan struct{})

			agent.ServiceRegisterStub = func(*api.AgentServiceRegistration) error {
				<-blockRegister
				close(blockRegisterDone)
				return nil
			}
		})

		JustBeforeEach(func() {
			registrationProcess = ifrit.Background(registrationRunner)
		})

		AfterEach(func() {
			close(blockRegister)
			Eventually(blockRegisterDone).Should(BeClosed())
			ginkgomon.Kill(registrationProcess)
		})

		It("does not become ready", func() {
			Consistently(registrationProcess.Ready()).ShouldNot(BeClosed())
		})

		It("shuts down without deregistering", func() {
			Eventually(agent.ServiceRegisterCallCount).Should(Equal(1))
			registrationProcess.Signal(os.Interrupt)
			Eventually(registrationProcess.Wait()).Should(Receive(BeNil()))
			Expect(agent.ServiceDeregisterCallCount()).Should(Equal(0))
		})
	})

	Context("when we fail to deregister the service", func() {
		var registrationError = errors.New("boom")
		BeforeEach(func() {
			agent.ServiceDeregisterReturns(registrationError)
		})

		JustBeforeEach(func() {
			registrationProcess = ginkgomon.Invoke(registrationRunner)
		})

		AfterEach(func() {
			ginkgomon.Kill(registrationProcess)
		})

		It("returns an error", func() {
			ginkgomon.Interrupt(registrationProcess)
			Eventually(registrationProcess.Wait()).Should(Receive(Equal(registrationError)))
		})
	})
})

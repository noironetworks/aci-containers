package diego_logging_client

import (
	"time"

	loggregator "code.cloudfoundry.org/go-loggregator"
	"github.com/cloudfoundry/sonde-go/events"
)

type noopIngressClient struct{}

func (*noopIngressClient) SendDuration(name string, value time.Duration, opts ...loggregator.EmitGaugeOption) error {
	return nil
}
func (*noopIngressClient) SendMebiBytes(name string, value int) error {
	return nil
}
func (*noopIngressClient) SendMetric(name string, value int, opts ...loggregator.EmitGaugeOption) error {
	return nil
}
func (*noopIngressClient) SendBytesPerSecond(name string, value float64) error {
	return nil
}
func (*noopIngressClient) SendRequestsPerSecond(name string, value float64) error {
	return nil
}
func (*noopIngressClient) IncrementCounter(name string) error {
	return nil
}
func (*noopIngressClient) IncrementCounterWithDelta(name string, value uint64) error {
	return nil
}
func (*noopIngressClient) SendAppLog(appID, message, sourceType, sourceInstance string) error {
	return nil
}
func (*noopIngressClient) SendAppErrorLog(appID, message, sourceType, sourceInstance string) error {
	return nil
}
func (*noopIngressClient) SendAppMetrics(metrics *events.ContainerMetric) error {
	return nil
}
func (*noopIngressClient) SendComponentMetric(name string, value float64, unit string) error {
	return nil
}

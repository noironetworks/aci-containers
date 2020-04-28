package diego_logging_client

import (
	"fmt"
	"time"

	loggregator "code.cloudfoundry.org/go-loggregator"
	"github.com/cloudfoundry/sonde-go/events"
)

// Config is the shared configuration between v1 and v2 clients.
type Config struct {
	UseV2API      bool   `json:"loggregator_use_v2_api"`
	APIPort       int    `json:"loggregator_api_port"`
	CACertPath    string `json:"loggregator_ca_path"`
	CertPath      string `json:"loggregator_cert_path"`
	KeyPath       string `json:"loggregator_key_path"`
	JobDeployment string `json:"loggregator_job_deployment"`
	JobName       string `json:"loggregator_job_name"`
	JobIndex      string `json:"loggregator_job_index"`
	JobIP         string `json:"loggregator_job_ip"`
	JobOrigin     string `json:"loggregator_job_origin"`

	BatchMaxSize       uint `json:"loggregator_batch_max_size"`
	BatchFlushInterval time.Duration
}

// IngressClient is the shared contract between v1 and v2 clients.
//go:generate counterfeiter -o testhelpers/fake_ingress_client.go . IngressClient
type IngressClient interface {
	SendDuration(name string, value time.Duration, opts ...loggregator.EmitGaugeOption) error
	SendMebiBytes(name string, value int) error
	SendMetric(name string, value int, opts ...loggregator.EmitGaugeOption) error
	SendBytesPerSecond(name string, value float64) error
	SendRequestsPerSecond(name string, value float64) error
	IncrementCounter(name string) error
	IncrementCounterWithDelta(name string, value uint64) error
	SendAppLog(appID, message, sourceType, sourceInstance string) error
	SendAppErrorLog(appID, message, sourceType, sourceInstance string) error
	SendAppMetrics(metrics *events.ContainerMetric) error
	SendComponentMetric(name string, value float64, unit string) error
}

// NewIngressClient returns a v2 client if the config.UseV2API is true, or a no op client.
func NewIngressClient(config Config) (IngressClient, error) {
	if config.UseV2API {
		return newV2IngressClient(config)
	}

	return new(noopIngressClient), nil
}

// NewV2IngressClient creates a V2 connection to the Loggregator API.
func newV2IngressClient(config Config) (IngressClient, error) {
	tlsConfig, err := loggregator.NewIngressTLSConfig(
		config.CACertPath,
		config.CertPath,
		config.KeyPath,
	)
	if err != nil {
		return nil, err
	}

	opts := []loggregator.IngressOption{
		// Whereas Metron will add tags for deployment, name, index, and ip,
		// it does not add job origin and so we must add it manually here.
		loggregator.WithTag("origin", config.JobOrigin),
	}

	if config.BatchMaxSize != 0 {
		opts = append(opts, loggregator.WithBatchMaxSize(config.BatchMaxSize))
	}

	if config.BatchFlushInterval != time.Duration(0) {
		opts = append(opts, loggregator.WithBatchFlushInterval(config.BatchFlushInterval))
	}

	if config.APIPort != 0 {
		opts = append(opts, loggregator.WithAddr(fmt.Sprintf("localhost:%d", config.APIPort)))
	}

	c, err := loggregator.NewIngressClient(tlsConfig, opts...)
	if err != nil {
		return nil, err
	}

	return client{client: c}, nil
}

type logClient interface {
	EmitLog(msg string, opts ...loggregator.EmitLogOption)
	EmitGauge(opts ...loggregator.EmitGaugeOption)
	EmitCounter(name string, opts ...loggregator.EmitCounterOption)
}

type client struct {
	client logClient
}

func (c client) SendDuration(name string, value time.Duration, opts ...loggregator.EmitGaugeOption) error {
	opts = append(opts, loggregator.WithGaugeValue(name, float64(value), "nanos"))
	c.client.EmitGauge(opts...)

	return nil
}

func (c client) SendMebiBytes(name string, value int) error {
	c.client.EmitGauge(
		loggregator.WithGaugeValue(name, float64(value), "MiB"),
	)
	return nil
}

func (c client) SendMetric(name string, value int, opts ...loggregator.EmitGaugeOption) error {
	opts = append(opts, loggregator.WithGaugeValue(name, float64(value), "Metric"))
	c.client.EmitGauge(opts...)

	return nil
}

func (c client) SendBytesPerSecond(name string, value float64) error {
	c.client.EmitGauge(
		loggregator.WithGaugeValue(name, value, "B/s"),
	)
	return nil
}

func (c client) SendRequestsPerSecond(name string, value float64) error {
	c.client.EmitGauge(
		loggregator.WithGaugeValue(name, value, "Req/s"),
	)
	return nil
}

func (c client) IncrementCounter(name string) error {
	c.client.EmitCounter(name)

	return nil
}

func (c client) IncrementCounterWithDelta(name string, value uint64) error {
	c.client.EmitCounter(name, loggregator.WithDelta(value))

	return nil
}

func (c client) SendAppLog(appID, message, sourceType, sourceInstance string) error {
	c.client.EmitLog(
		message,
		loggregator.WithAppInfo(appID, sourceType, sourceInstance),
		loggregator.WithStdout(),
	)
	return nil
}

func (c client) SendAppErrorLog(appID, message, sourceType, sourceInstance string) error {
	c.client.EmitLog(
		message,
		loggregator.WithAppInfo(appID, sourceType, sourceInstance),
	)
	return nil
}

func (c client) SendAppMetrics(m *events.ContainerMetric) error {
	c.client.EmitGauge(
		loggregator.WithGaugeValue("cpu", m.GetCpuPercentage(), "percentage"),
		loggregator.WithGaugeValue("memory", float64(m.GetMemoryBytes()), "bytes"),
		loggregator.WithGaugeValue("disk", float64(m.GetDiskBytes()), "bytes"),
		loggregator.WithGaugeValue("memory_quota", float64(m.GetMemoryBytesQuota()), "bytes"),
		loggregator.WithGaugeValue("disk_quota", float64(m.GetDiskBytesQuota()), "bytes"),
		loggregator.WithGaugeAppInfo(m.GetApplicationId(), int(m.GetInstanceIndex())),
	)

	return nil
}

func (c client) SendComponentMetric(name string, value float64, unit string) error {
	c.client.EmitGauge(
		loggregator.WithGaugeValue(name, value, unit),
	)

	return nil
}

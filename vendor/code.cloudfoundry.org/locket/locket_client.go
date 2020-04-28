package locket

import (
	"time"

	"code.cloudfoundry.org/cfhttp"
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/locket/models"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type ClientLocketConfig struct {
	LocketAddress        string `json:"locket_address,omitempty" yaml:"locket_address,omitempty"`
	LocketCACertFile     string `json:"locket_ca_cert_file,omitempty" yaml:"locket_ca_cert_file,omitempty"`
	LocketClientCertFile string `json:"locket_client_cert_file,omitempty" yaml:"locket_client_cert_file,omitempty"`
	LocketClientKeyFile  string `json:"locket_client_key_file,omitempty" yaml:"locket_client_key_file,omitempty"`
}

func NewClientSkipCertVerify(logger lager.Logger, config ClientLocketConfig) (models.LocketClient, error) {
	return newClientInternal(logger, config, true)
}

func NewClient(logger lager.Logger, config ClientLocketConfig) (models.LocketClient, error) {
	return newClientInternal(logger, config, false)
}

func newClientInternal(logger lager.Logger, config ClientLocketConfig, skipCertVerify bool) (models.LocketClient, error) {
	if config.LocketAddress == "" {
		logger.Fatal("invalid-locket-config", nil)
	}

	locketTLSConfig, err := cfhttp.NewTLSConfig(config.LocketClientCertFile, config.LocketClientKeyFile, config.LocketCACertFile)
	if err != nil {
		logger.Error("failed-to-open-tls-config", err, lager.Data{"keypath": config.LocketClientKeyFile, "certpath": config.LocketClientCertFile, "capath": config.LocketCACertFile})
		return nil, err
	}
	locketTLSConfig.InsecureSkipVerify = skipCertVerify

	conn, err := grpc.Dial(
		config.LocketAddress,
		grpc.WithTransportCredentials(credentials.NewTLS(locketTLSConfig)),
		grpc.WithBlock(),
		grpc.WithTimeout(1*time.Second),
	)
	if err != nil {
		return nil, err
	}
	return models.NewLocketClient(conn), nil
}

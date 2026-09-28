// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package elasticsearchauth provides Elasticsearch HTTP authentication for OTel components.
package elasticsearchauth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configopaque"
)

// Config configures the Elasticsearch authentication extension.
//
// The embedded HTTP configuration supplies the TLS, proxy, header, pool, and
// keepalive settings used by transports returned from RoundTripper. Its
// endpoint, timeout, auth, middleware, cookie, and compression settings are
// intentionally unsupported by this extension.
type Config struct {
	ClientConfig confighttp.ClientConfig `mapstructure:",squash"`

	// Endpoints contains the resolved Elasticsearch HTTP(S) endpoints.
	Endpoints []string `mapstructure:"endpoints"`

	// User configures HTTP Basic authentication with Password.
	User string `mapstructure:"user"`
	// Password configures HTTP Basic authentication with User.
	Password configopaque.String `mapstructure:"password"`
	// APIKey configures Elasticsearch ApiKey authentication. It must be the
	// base64-encoded id:key representation accepted by Elasticsearch.
	APIKey configopaque.String `mapstructure:"api_key"`
}

func createDefaultConfig() component.Config {
	return &Config{ClientConfig: confighttp.NewDefaultClientConfig()}
}

// Validate validates configuration relationships without accessing TLS files.
func (c *Config) Validate() error {
	if len(c.Endpoints) == 0 {
		return errors.New("at least one endpoint must be configured")
	}
	if c.ClientConfig.Endpoint != "" {
		return unsupportedFieldError("endpoint")
	}
	if c.ClientConfig.Timeout != 0 {
		return unsupportedFieldError("timeout")
	}
	if c.ClientConfig.Auth.HasValue() {
		return unsupportedFieldError("auth")
	}
	if len(c.ClientConfig.Middlewares) != 0 {
		return unsupportedFieldError("middlewares")
	}
	if c.ClientConfig.Cookies.HasValue() {
		return unsupportedFieldError("cookies")
	}
	if c.ClientConfig.Compression.IsCompressed() {
		return unsupportedFieldError("compression")
	}

	for _, endpoint := range c.Endpoints {
		u, err := parseHTTPURL(endpoint)
		if err != nil {
			return fmt.Errorf("invalid endpoint: %w", err)
		}
		if u.User != nil && (c.User != "" || c.Password != "" || c.APIKey != "") {
			return errors.New("endpoint userinfo cannot be combined with configured authentication")
		}
	}

	if c.ClientConfig.ProxyURL != "" {
		if _, err := parseHTTPURL(c.ClientConfig.ProxyURL); err != nil {
			return fmt.Errorf("invalid proxy_url: %w", err)
		}
	}

	if err := validateAuthentication(c.User, c.Password, c.APIKey); err != nil {
		return err
	}

	return nil
}

func unsupportedFieldError(field string) error {
	switch field {
	case "endpoint":
		return errors.New("endpoint is unsupported; configure endpoints instead")
	case "timeout":
		return errors.New("timeout is unsupported; consumers own request deadlines")
	case "auth":
		return errors.New("nested auth is unsupported")
	case "compression_params":
		return errors.New("compression_params are unsupported")
	case "compression":
		return errors.New("compression is unsupported")
	default:
		return fmt.Errorf("%s are unsupported", field)
	}
}

func parseHTTPURL(rawURL string) (*url.URL, error) {
	if rawURL == "" {
		return nil, errors.New("URL must not be empty")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("URL must be a fully resolved HTTP(S) URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("URL scheme must be http or https")
	}
	if u.Host == "" {
		return nil, errors.New("URL host must not be empty")
	}
	if u.Fragment != "" {
		return nil, errors.New("URL fragments are unsupported")
	}
	return u, nil
}

func validateAuthentication(user string, password, apiKey configopaque.String) error {
	hasUser := user != ""
	hasPassword := password != ""
	hasAPIKey := apiKey != ""
	if hasUser != hasPassword {
		return errors.New("user and password must be configured together")
	}
	if hasAPIKey && hasUser {
		return errors.New("api_key cannot be combined with basic authentication")
	}
	if !hasAPIKey {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(string(apiKey))
	if err != nil {
		return errors.New("api_key must be base64-encoded id:key")
	}
	id, key, found := strings.Cut(string(decoded), ":")
	if !found || id == "" || key == "" {
		return errors.New("api_key must be base64-encoded id:key")
	}
	return nil
}

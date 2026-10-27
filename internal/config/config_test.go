package config

import "testing"

func TestValidateStatusExposure(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{
			name: "loopback status listener is allowed",
		},
		{
			name: "remote listener requires explicit opt in",
			mutate: func(cfg *Config) {
				cfg.StatusAddr = "0.0.0.0:9095"
			},
			wantErr: true,
		},
		{
			name: "remote listener requires a token",
			mutate: func(cfg *Config) {
				cfg.StatusAddr = "0.0.0.0:9095"
				cfg.StatusAllowRemote = true
			},
			wantErr: true,
		},
		{
			name: "remote listener with token is allowed",
			mutate: func(cfg *Config) {
				cfg.StatusAddr = "0.0.0.0:9095"
				cfg.StatusAllowRemote = true
				cfg.StatusAuthToken = "test-token"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			if tt.mutate != nil {
				tt.mutate(cfg)
			}

			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultDoesNotEnableInlineProxy(t *testing.T) {
	cfg := Default()
	if cfg.ProxyEnabled {
		t.Fatal("Default() must not enable the in-line proxy without an explicit backend")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateProxyConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{
			name: "valid proxy configuration",
			mutate: func(cfg *Config) {
				cfg.ProxyEnabled = true
				cfg.ListenAddr = "127.0.0.1:8080"
				cfg.BackendURL = "http://127.0.0.1:8081"
			},
		},
		{
			name: "missing backend",
			mutate: func(cfg *Config) {
				cfg.ProxyEnabled = true
				cfg.BackendURL = ""
			},
			wantErr: true,
		},
		{
			name: "non-http backend",
			mutate: func(cfg *Config) {
				cfg.ProxyEnabled = true
				cfg.BackendURL = "127.0.0.1:8081"
			},
			wantErr: true,
		},
		{
			name: "invalid listen address",
			mutate: func(cfg *Config) {
				cfg.ProxyEnabled = true
				cfg.ListenAddr = "not-a-host-port"
			},
			wantErr: true,
		},
		{
			name: "mismatched tls cert without key",
			mutate: func(cfg *Config) {
				cfg.ProxyEnabled = true
				cfg.TLSCertFile = "/etc/ssl/certs/server.crt"
			},
			wantErr: true,
		},
		{
			name: "invalid trusted_proxies CIDR",
			mutate: func(cfg *Config) {
				cfg.TrustedProxies = []string{"not-an-ip"}
			},
			wantErr: true,
		},
		{
			name: "valid trusted_proxies IPs and CIDRs",
			mutate: func(cfg *Config) {
				cfg.TrustedProxies = []string{"127.0.0.1", "10.0.0.0/8", "::1/128"}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			tt.mutate(cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAssignsRequestReadTimeout(t *testing.T) {
	cfg := Default()
	cfg.RequestReadTimeout = 0

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if cfg.RequestReadTimeout <= 0 {
		t.Fatal("Validate() did not assign a positive request read timeout")
	}
}

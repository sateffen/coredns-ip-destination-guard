package ipdestinationguard

import (
	"net"
	"strings"
	"testing"

	"github.com/coredns/caddy"
)

func TestGetIPRangeEnd(t *testing.T) {
	tests := []struct {
		startIP  net.IP
		maskBits uint
		endIP    net.IP
	}{
		{
			startIP:  net.ParseIP("192.168.0.0").To4(),
			maskBits: 24,
			endIP:    net.ParseIP("192.168.1.0").To4(),
		},
		{
			startIP:  net.ParseIP("192.168.0.42").To4(),
			maskBits: 32,
			endIP:    net.ParseIP("192.168.0.43").To4(),
		},
		{
			startIP:  net.ParseIP("fe80::ab12:abcd:1234:0000").To16(),
			maskBits: 112,
			endIP:    net.ParseIP("fe80::ab12:abcd:1235:0000").To16(),
		},
	}

	for _, test := range tests {
		endIP := getIPRangeEnd(test.startIP, test.maskBits)

		if !endIP.Equal(test.endIP) {
			t.Errorf("Received unexpected endIP: %v - testcase: %+v", endIP, test)
		}
	}
}

func TestGetIPRange(t *testing.T) {
	tests := []struct {
		cidrStr   string
		startIP   net.IP
		endIP     net.IP
		shourdErr bool
	}{
		{
			cidrStr:   "192.168.0.0/24",
			startIP:   net.ParseIP("192.168.0.0").To4(),
			endIP:     net.ParseIP("192.168.1.0").To4(),
			shourdErr: false,
		},
		{
			cidrStr:   "192.168.0.42",
			startIP:   net.ParseIP("192.168.0.42").To4(),
			endIP:     net.ParseIP("192.168.0.43").To4(),
			shourdErr: false,
		},
		{
			cidrStr:   "fe80::ab12:abcd:1234:0042/64",
			startIP:   net.ParseIP("fe80::").To16(),
			endIP:     net.ParseIP("fe80:0000:0000:0001::").To16(),
			shourdErr: false,
		},
		{
			cidrStr:   "fe80::ab12:abcd:1234:0042",
			startIP:   net.ParseIP("fe80::ab12:abcd:1234:0042").To16(),
			endIP:     net.ParseIP("fe80::ab12:abcd:1234:0043").To16(),
			shourdErr: false,
		},
		{
			cidrStr:   "292.168.0.0/24",
			shourdErr: true,
		},
	}

	for _, test := range tests {
		startIP, endIP, err := getIPRange(test.cidrStr)

		if !test.shourdErr && err != nil {
			t.Errorf("Received unexpected err: %v - testcase: %+v", err, test)
		}

		if !test.shourdErr && !startIP.Equal(test.startIP) {
			t.Errorf("Received unexpected startIP: %v - testcase: %+v", startIP, test)
		}

		if !test.shourdErr && !endIP.Equal(test.endIP) {
			t.Errorf("Received unexpected endIP: %v - testcase: %+v", endIP, test)
		}
	}
}

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectedMode    Mode
		expectedIPCount int // number of IPs (including start/end pairs)
		shouldError     bool
		errorContains   string
	}{
		// Legacy single-line format tests
		{
			name:            "single-line with mode only",
			input:           "ipdestinationguard nft-local",
			expectedMode:    "nft-local",
			expectedIPCount: 0,
			shouldError:     false,
		},
		{
			name:            "single-line with mode and single IP",
			input:           "ipdestinationguard nft-gateway 192.168.1.1",
			expectedMode:    "nft-gateway",
			expectedIPCount: 2, // start and end IP
			shouldError:     false,
		},
		{
			name:            "single-line with mode and CIDR",
			input:           "ipdestinationguard nft-local 10.0.0.0/24",
			expectedMode:    "nft-local",
			expectedIPCount: 2,
			shouldError:     false,
		},
		{
			name:            "single-line with multiple IPs and CIDRs",
			input:           "ipdestinationguard nft-local 192.168.1.1 10.0.0.0/8 172.16.0.0/12",
			expectedMode:    "nft-local",
			expectedIPCount: 6, // 3 ranges = 6 IPs
			shouldError:     false,
		},
		{
			name:            "single-line with IPv6",
			input:           "ipdestinationguard nft-gateway fe80::1",
			expectedMode:    "nft-gateway",
			expectedIPCount: 2,
			shouldError:     false,
		},
		{
			name:          "single-line with invalid IP",
			input:         "ipdestinationguard nft-local 999.999.999.999",
			shouldError:   true,
			errorContains: "can't extract ip range",
		},

		// Block format tests
		{
			name: "block with mode only",
			input: `ipdestinationguard {
				mode nft-local
			}`,
			expectedMode:    "nft-local",
			expectedIPCount: 0,
			shouldError:     false,
		},
		{
			name: "block with mode and single IP",
			input: `ipdestinationguard {
				mode nft-gateway
				allowedIPs 192.168.1.1
			}`,
			expectedMode:    "nft-gateway",
			expectedIPCount: 2,
			shouldError:     false,
		},
		{
			name: "block with mode and multiple IPs on one line",
			input: `ipdestinationguard {
				mode nft-local
				allowedIPs 192.168.1.1 10.0.0.0/24 172.16.0.1
			}`,
			expectedMode:    "nft-local",
			expectedIPCount: 6,
			shouldError:     false,
		},
		{
			name: "block with multiple allowedIPs directives",
			input: `ipdestinationguard {
				mode nft-local
				allowedIPs 192.168.1.1
				allowedIPs 10.0.0.0/24
				allowedIPs 172.16.0.1
			}`,
			expectedMode:    "nft-local",
			expectedIPCount: 6,
			shouldError:     false,
		},
		{
			name: "block with IPv6 CIDR",
			input: `ipdestinationguard {
				mode nft-gateway
				allowedIPs fe80::/64
			}`,
			expectedMode:    "nft-gateway",
			expectedIPCount: 2,
			shouldError:     false,
		},
		{
			name: "block with mixed IPv4 and IPv6",
			input: `ipdestinationguard {
				mode nft-local
				allowedIPs 192.168.1.0/24 fe80::1
			}`,
			expectedMode:    "nft-local",
			expectedIPCount: 4,
			shouldError:     false,
		},
		{
			name: "empty block",
			input: `ipdestinationguard {
			}`,
			expectedMode:    "",
			expectedIPCount: 0,
			shouldError:     false,
		},

		// Error cases
		{
			name: "block with unknown directive",
			input: `ipdestinationguard {
				mode nft-local
				invalidDirective value
			}`,
			shouldError:   true,
			errorContains: "unknown directive",
		},
		{
			name: "block with mode but no value",
			input: `ipdestinationguard {
				mode
			}`,
			shouldError:   true,
			errorContains: "mode directive expects exactly one argument",
		},
		{
			name: "block with mode and multiple values",
			input: `ipdestinationguard {
				mode nft-local nft-gateway
			}`,
			shouldError:   true,
			errorContains: "mode directive expects exactly one argument",
		},
		{
			name: "block with allowedIPs but no value",
			input: `ipdestinationguard {
				mode nft-local
				allowedIPs
			}`,
			shouldError:   true,
			errorContains: "allowedIPs directive requires at least one IP",
		},
		{
			name: "block with invalid IP in allowedIPs",
			input: `ipdestinationguard {
				mode nft-local
				allowedIPs 999.999.999.999
			}`,
			shouldError:   true,
			errorContains: "can't extract ip range",
		},
		{
			name: "block with invalid CIDR in allowedIPs",
			input: `ipdestinationguard {
				mode nft-local
				allowedIPs 192.168.1.0/99
			}`,
			shouldError:   true,
			errorContains: "can't extract ip range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tt.input)
			c.Next() // consume plugin name

			config, err := parseConfig(c)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error containing '%s', but got no error", tt.errorContains)
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', but got: %v", tt.errorContains, err)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if config.mode != tt.expectedMode {
				t.Errorf("Expected mode '%s', got '%s'", tt.expectedMode, config.mode)
			}

			if len(config.allowedIPs) != tt.expectedIPCount {
				t.Errorf("Expected %d IPs, got %d", tt.expectedIPCount, len(config.allowedIPs))
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name          string
		config        *parsedConfig
		shouldError   bool
		errorContains string
	}{
		{
			name: "valid nft-local mode",
			config: &parsedConfig{
				mode:       ModeNFTLocal,
				allowedIPs: []net.IP{},
			},
			shouldError: false,
		},
		{
			name: "valid nft-gateway mode",
			config: &parsedConfig{
				mode:       ModeNFTGateway,
				allowedIPs: []net.IP{},
			},
			shouldError: false,
		},
		{
			name: "valid config with IPs",
			config: &parsedConfig{
				mode: ModeNFTLocal,
				allowedIPs: []net.IP{
					net.ParseIP("192.168.1.1"),
					net.ParseIP("192.168.1.2"),
				},
			},
			shouldError: false,
		},
		{
			name: "empty mode",
			config: &parsedConfig{
				mode:       "",
				allowedIPs: []net.IP{},
			},
			shouldError:   true,
			errorContains: "mode is required",
		},
		{
			name: "invalid mode value",
			config: &parsedConfig{
				mode:       "invalid-mode",
				allowedIPs: []net.IP{},
			},
			shouldError:   true,
			errorContains: "invalid mode",
		},
		{
			name: "invalid mode - local instead of nft-local",
			config: &parsedConfig{
				mode:       "local",
				allowedIPs: []net.IP{},
			},
			shouldError:   true,
			errorContains: "invalid mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error containing '%s', but got no error", tt.errorContains)
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', but got: %v", tt.errorContains, err)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

package ipdestinationguard

import (
	"net"
	"strings"
	"testing"

	"github.com/coredns/caddy"
)

func TestInnerGetIPRange(t *testing.T) {
	tests := []struct {
		startIP       net.IP
		maskedBits    uint
		resultStartIP net.IP
		resultEndIP   net.IP
		resultOpenEnd bool
	}{
		{
			startIP:       net.ParseIP("192.168.0.0").To4(),
			maskedBits:    24,
			resultStartIP: net.ParseIP("192.168.0.0").To4(),
			resultEndIP:   net.ParseIP("192.168.1.0").To4(),
			resultOpenEnd: false,
		},
		{
			startIP:       net.ParseIP("192.168.0.42").To4(),
			maskedBits:    32,
			resultStartIP: net.ParseIP("192.168.0.42").To4(),
			resultEndIP:   net.ParseIP("192.168.0.43").To4(),
			resultOpenEnd: false,
		},
		{
			startIP:       net.ParseIP("192.168.10.42").To4(),
			maskedBits:    24,
			resultStartIP: net.ParseIP("192.168.10.0").To4(),
			resultEndIP:   net.ParseIP("192.168.11.0").To4(),
			resultOpenEnd: false,
		},
		{
			startIP:       net.ParseIP("fe80::ab12:abcd:1234:0000").To16(),
			maskedBits:    112,
			resultStartIP: net.ParseIP("fe80::ab12:abcd:1234:0000").To16(),
			resultEndIP:   net.ParseIP("fe80::ab12:abcd:1235:0000").To16(),
			resultOpenEnd: false,
		},
		{
			// Carry must propagate across byte boundaries.
			startIP:       net.ParseIP("10.255.0.0").To4(),
			maskedBits:    16,
			resultStartIP: net.ParseIP("10.255.0.0").To4(),
			resultEndIP:   net.ParseIP("11.0.0.0").To4(),
			resultOpenEnd: false,
		},
		{
			// Carry must propagate across byte boundaries.
			startIP:       net.ParseIP("fe80::ffff:ffff").To16(),
			maskedBits:    112,
			resultStartIP: net.ParseIP("fe80::ffff:0").To16(),
			resultEndIP:   net.ParseIP("fe80::1:0:0").To16(),
			resultOpenEnd: false,
		},
		{
			// Largest representable range end in IPv4.
			startIP:       net.ParseIP("255.255.255.254").To4(),
			maskedBits:    32,
			resultStartIP: net.ParseIP("255.255.255.254").To4(),
			resultEndIP:   net.ParseIP("255.255.255.255").To4(),
			resultOpenEnd: false,
		},
		{
			// Full-range CIDRs: the exclusive end overflows the address space.
			startIP:       net.ParseIP("0.0.0.0").To4(),
			maskedBits:    0,
			resultStartIP: net.ParseIP("0.0.0.0").To4(),
			resultEndIP:   nil,
			resultOpenEnd: true,
		},
		{
			startIP:       net.IP(make([]byte, 16)),
			maskedBits:    0,
			resultStartIP: net.IP(make([]byte, 16)),
			resultEndIP:   nil,
			resultOpenEnd: true,
		},
		{
			// Single max address: end would be one past the address space.
			startIP:       net.ParseIP("255.255.255.255").To4(),
			maskedBits:    32,
			resultStartIP: net.ParseIP("255.255.255.255").To4(),
			resultEndIP:   nil,
			resultOpenEnd: true,
		},
		{
			startIP:       net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").To16(),
			maskedBits:    128,
			resultStartIP: net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").To16(),
			resultEndIP:   nil,
			resultOpenEnd: true,
		},
		{
			startIP:       net.ParseIP("0.0.0.0").To4(),
			maskedBits:    1,
			resultStartIP: net.ParseIP("0.0.0.0").To4(),
			resultEndIP:   net.ParseIP("128.0.0.0").To4(),
			resultOpenEnd: false,
		},
		{
			startIP:       net.ParseIP("::ffff:192.168.123.123"),
			maskedBits:    120,
			resultStartIP: net.ParseIP("192.168.123.0").To4(),
			resultEndIP:   net.ParseIP("192.168.124.0").To4(),
			resultOpenEnd: false,
		},
	}

	for _, test := range tests {
		parsedIPRange := innerGetIPRange(test.startIP, test.maskedBits)

		if !parsedIPRange.start.Equal(test.resultStartIP) {
			t.Errorf("Received parsedIPRange.start is unexpected: %v - testcase: %+v", parsedIPRange.start, test)
			continue
		}

		if test.resultOpenEnd {
			if !parsedIPRange.openEnd {
				t.Errorf("Expected parsedIPRange to be open ended, but was not - testcase %+v", test)
			}
		} else {
			if !parsedIPRange.end.Equal(test.resultEndIP) {
				t.Errorf("Received parsedIPRange.end is unexpected: %v - testcase: %+v", parsedIPRange.end, test)
			}
		}
	}
}

func TestGetIPRange(t *testing.T) {
	// Note: We trust, that the test for innerGetIPRange creates a valid parsedIPResult, so
	// we test only for start ip
	tests := []struct {
		cidrStr   string
		startIP   net.IP
		shourdErr bool
	}{
		{
			cidrStr:   "192.168.0.0/24",
			startIP:   net.ParseIP("192.168.0.0").To4(),
			shourdErr: false,
		},
		{
			cidrStr:   "192.168.0.42",
			startIP:   net.ParseIP("192.168.0.42").To4(),
			shourdErr: false,
		},
		{
			cidrStr:   "fe80::ab12:abcd:1234:0042/64",
			startIP:   net.ParseIP("fe80::").To16(),
			shourdErr: false,
		},
		{
			cidrStr:   "fe80::ab12:abcd:1234:0042",
			startIP:   net.ParseIP("fe80::ab12:abcd:1234:0042").To16(),
			shourdErr: false,
		},
		// invalid inputs
		{
			cidrStr:   "292.168.0.0/24",
			shourdErr: true,
		},
		{
			cidrStr:   "0.0.0.0/0",
			shourdErr: true,
		},
		{
			cidrStr:   "::/0",
			shourdErr: true,
		},
		// weird patterns
		{
			cidrStr:   "::ffff:192.168.0.0/120",
			shourdErr: true,
		},
		{
			cidrStr:   "::ffff:192.168.0.42",
			startIP:   net.ParseIP("192.168.0.42").To4(),
			shourdErr: false,
		},
	}

	for _, test := range tests {
		parsedIPRange, err := getIPRange(test.cidrStr)

		if test.shourdErr {
			if err == nil {
				t.Errorf("Expected error, but testcase succeeded - testcase %+v", test)
			}
			continue
		}

		if err != nil || parsedIPRange == nil {
			t.Errorf("Received error, but didn't expect one \"%s\" - testcase %+v", err, test)
			continue
		}

		if !parsedIPRange.start.Equal(test.startIP) {
			t.Errorf("Received parsedIPRange.start is unexpected: %v - testcase: %+v", parsedIPRange.start, test)
		}
	}
}

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name                        string
		input                       string
		expectedMode                Mode
		expectedIPRangeCount        int
		expectedLocalIPRangeCount   int
		expectedGatewayIPRangeCount int
		shouldError                 bool
		errorContains               string
	}{
		// Legacy single-line format tests
		{
			name:                 "single-line with mode only",
			input:                "ipdestinationguard nft-local",
			expectedMode:         "nft-local",
			expectedIPRangeCount: 0,
			shouldError:          false,
		},
		{
			name:                 "single-line with mode and single IP",
			input:                "ipdestinationguard nft-gateway 192.168.1.1",
			expectedMode:         "nft-gateway",
			expectedIPRangeCount: 1,
			shouldError:          false,
		},
		{
			name:                 "single-line with mode and CIDR",
			input:                "ipdestinationguard nft-local 10.0.0.0/24",
			expectedMode:         "nft-local",
			expectedIPRangeCount: 1,
			shouldError:          false,
		},
		{
			name:                 "single-line with multiple IPs and CIDRs",
			input:                "ipdestinationguard nft-local 192.168.1.1 10.0.0.0/8 172.16.0.0/12",
			expectedMode:         "nft-local",
			expectedIPRangeCount: 3,
			shouldError:          false,
		},
		{
			name:                 "single-line with IPv6",
			input:                "ipdestinationguard nft-gateway fe80::1",
			expectedMode:         "nft-gateway",
			expectedIPRangeCount: 1,
			shouldError:          false,
		},
		{
			name:                 "single-line with nft-both mode",
			input:                "ipdestinationguard nft-both 192.168.1.1",
			expectedMode:         "nft-both",
			expectedIPRangeCount: 1,
			shouldError:          false,
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
			expectedMode:         "nft-local",
			expectedIPRangeCount: 0,
			shouldError:          false,
		},
		{
			name: "block with mode and single IP",
			input: `ipdestinationguard {
				mode nft-gateway
				allowedIPs 192.168.1.1
			}`,
			expectedMode:         "nft-gateway",
			expectedIPRangeCount: 1,
			shouldError:          false,
		},
		{
			name: "block with mode and multiple IPs on one line",
			input: `ipdestinationguard {
				mode nft-local
				allowedIPs 192.168.1.1 10.0.0.0/24 172.16.0.1
			}`,
			expectedMode:         "nft-local",
			expectedIPRangeCount: 3,
			shouldError:          false,
		},
		{
			name: "block with multiple allowedIPs directives",
			input: `ipdestinationguard {
				mode nft-local
				allowedIPs 192.168.1.1
				allowedIPs 10.0.0.0/24
				allowedIPs 172.16.0.1
			}`,
			expectedMode:         "nft-local",
			expectedIPRangeCount: 3,
			shouldError:          false,
		},
		{
			name: "block with IPv6 CIDR",
			input: `ipdestinationguard {
				mode nft-gateway
				allowedIPs fe80::/64
			}`,
			expectedMode:         "nft-gateway",
			expectedIPRangeCount: 1,
			shouldError:          false,
		},
		{
			name: "block with mixed IPv4 and IPv6",
			input: `ipdestinationguard {
				mode nft-local
				allowedIPs 192.168.1.0/24 fe80::1
			}`,
			expectedMode:         "nft-local",
			expectedIPRangeCount: 2,
			shouldError:          false,
		},
		{
			name: "block with nft-both mode",
			input: `ipdestinationguard {
				mode nft-both
				allowedIPs 192.168.1.1 10.0.0.0/24
			}`,
			expectedMode:         "nft-both",
			expectedIPRangeCount: 2,
			shouldError:          false,
		},
		{
			name: "block with allowedLocalIPs",
			input: `ipdestinationguard {
				mode nft-local
				allowedIPs 9.9.9.9
				allowedLocalIPs 10.88.0.0/16
			}`,
			expectedMode:                "nft-local",
			expectedIPRangeCount:        1,
			expectedLocalIPRangeCount:   1,
			expectedGatewayIPRangeCount: 0,
			shouldError:                 false,
		},
		{
			name: "block with allowedGatewayIPs",
			input: `ipdestinationguard {
				mode nft-gateway
				allowedIPs 9.9.9.9
				allowedGatewayIPs 192.168.100.0/24
			}`,
			expectedMode:                "nft-gateway",
			expectedIPRangeCount:        1,
			expectedLocalIPRangeCount:   0,
			expectedGatewayIPRangeCount: 1,
			shouldError:                 false,
		},
		{
			name: "block with nft-both and all IP types",
			input: `ipdestinationguard {
				mode nft-both
				allowedIPs 9.9.9.9 149.112.112.112
				allowedLocalIPs 10.88.0.0/16
				allowedGatewayIPs 192.168.100.0/24
			}`,
			expectedMode:                "nft-both",
			expectedIPRangeCount:        2,
			expectedLocalIPRangeCount:   1,
			expectedGatewayIPRangeCount: 1,
			shouldError:                 false,
		},
		{
			name: "block with multiple allowedLocalIPs directives",
			input: `ipdestinationguard {
				mode nft-local
				allowedLocalIPs 10.88.0.0/16
				allowedLocalIPs 172.16.0.0/12
			}`,
			expectedMode:                "nft-local",
			expectedIPRangeCount:        0,
			expectedLocalIPRangeCount:   2,
			expectedGatewayIPRangeCount: 0,
			shouldError:                 false,
		},
		{
			name: "empty block",
			input: `ipdestinationguard {
			}`,
			expectedMode:         "",
			expectedIPRangeCount: 0,
			shouldError:          false,
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

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", test.input)
			c.Next() // consume plugin name

			config, err := parseConfig(c)

			if test.shouldError {
				if err == nil {
					t.Errorf("Expected error containing '%s', but got no error", test.errorContains)
					return
				}
				if test.errorContains != "" && !strings.Contains(err.Error(), test.errorContains) {
					t.Errorf("Expected error containing '%s', but got: %v", test.errorContains, err)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if config.mode != test.expectedMode {
				t.Errorf("Expected mode '%s', got '%s'", test.expectedMode, config.mode)
			}

			if len(config.allowedIPs) != test.expectedIPRangeCount {
				t.Errorf("Expected %d allowedIPs, got %d", test.expectedIPRangeCount, len(config.allowedIPs))
			}

			if len(config.allowedLocalIPs) != test.expectedLocalIPRangeCount {
				t.Errorf("Expected %d allowedLocalIPs, got %d", test.expectedLocalIPRangeCount, len(config.allowedLocalIPs))
			}

			if len(config.allowedGatewayIPs) != test.expectedGatewayIPRangeCount {
				t.Errorf("Expected %d allowedGatewayIPs, got %d", test.expectedGatewayIPRangeCount, len(config.allowedGatewayIPs))
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
				allowedIPs: []parsedIPRange{},
			},
			shouldError: false,
		},
		{
			name: "valid nft-gateway mode",
			config: &parsedConfig{
				mode:       ModeNFTGateway,
				allowedIPs: []parsedIPRange{},
			},
			shouldError: false,
		},
		{
			name: "valid config with IPs",
			config: &parsedConfig{
				mode: ModeNFTLocal,
				allowedIPs: []parsedIPRange{
					innerGetIPRange(net.ParseIP("192.168.1.1"), 24),
					innerGetIPRange(net.ParseIP("192.168.9.9"), 24),
				},
			},
			shouldError: false,
		},
		{
			name: "valid nft-both mode",
			config: &parsedConfig{
				mode:       ModeNFTBoth,
				allowedIPs: []parsedIPRange{},
			},
			shouldError: false,
		},
		{
			name: "empty mode",
			config: &parsedConfig{
				mode:       "",
				allowedIPs: []parsedIPRange{},
			},
			shouldError:   true,
			errorContains: "mode is required",
		},
		{
			name: "invalid mode value",
			config: &parsedConfig{
				mode:       "invalid-mode",
				allowedIPs: []parsedIPRange{},
			},
			shouldError:   true,
			errorContains: "invalid mode",
		},
		{
			name: "invalid mode - local instead of nft-local",
			config: &parsedConfig{
				mode:       "local",
				allowedIPs: []parsedIPRange{},
			},
			shouldError:   true,
			errorContains: "invalid mode",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateConfig(test.config)

			if test.shouldError {
				if err == nil {
					t.Errorf("Expected error containing '%s', but got no error", test.errorContains)
					return
				}
				if test.errorContains != "" && !strings.Contains(err.Error(), test.errorContains) {
					t.Errorf("Expected error containing '%s', but got: %v", test.errorContains, err)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

package ipdestinationguard

import (
	"fmt"
	"math/big"
	"net"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
)

// Mode represents the operation mode of this plugin.
type Mode string

// Valid mode constants
const (
	ModeNFTLocal   Mode = "nft-local"
	ModeNFTGateway Mode = "nft-gateway"
)

type parsedConfig struct {
	mode       Mode
	allowedIPs []net.IP
}

// define a named logger for nice logging.
var log = clog.NewWithPlugin("ipdestinationguard")

func init() { plugin.Register("ipdestinationguard", setup) }

func setup(c *caddy.Controller) error {
	// First, skip the first token, which is the plugin name "ipdestinationguard"
	c.Next()

	// Second, parse configuration
	config, err := parseConfig(c)
	if err != nil {
		return plugin.Error("ipdestinationguard", err)
	}

	// Third, validate the parsed configuration
	err = validateConfig(config)
	if err != nil {
		return plugin.Error("ipdestinationguard", err)
	}

	// The create the manager based on the validated config
	var dgManager DestinationGuardManager
	dgManager, err = NewNFTablesManager(config)
	if err != nil {
		return plugin.Error("ipdestinationguard", err)
	}

	// And finally, register plugin with the dnsserver
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return IPDestinationGuard{Next: next, DGManager: dgManager}
	})

	return nil
}

// parseConfig extracts configuration values from given the Caddy controller.
// It supports both single-line format (legacy) and block format:
//   - Single-line: ipdestinationguard nft-local 1.2.3.4 5.6.7.0/24
//   - Block format: ipdestinationguard {
//     mode nft-local
//     allowedIPs 1.2.3.4 5.6.7.0/24
//     }
func parseConfig(c *caddy.Controller) (*parsedConfig, error) {
	config := &parsedConfig{
		mode:       "", // Empty string = invalid, will fail validation
		allowedIPs: make([]net.IP, 0, 4),
	}

	// Check for single-line format
	allArgs := c.RemainingArgs()
	if len(allArgs) > 0 {
		// Single-line format: ipdestinationguard mode cidr1 cidr2 ...
		config.mode = Mode(allArgs[0])

		for _, ipString := range allArgs[1:] {
			startIP, endIP, err := getIPRange(ipString)
			if err != nil {
				return nil, err
			}

			config.allowedIPs = append(config.allowedIPs, startIP)
			config.allowedIPs = append(config.allowedIPs, endIP)
		}

		return config, nil
	}

	// Block format parsing
	for c.NextBlock() {
		directive := c.Val()

		switch directive {
		case "mode":
			args := c.RemainingArgs()
			if len(args) != 1 {
				return nil, c.Errf("mode directive expects exactly one argument, got %d", len(args))
			}
			config.mode = Mode(args[0])

		case "allowedIPs":
			args := c.RemainingArgs()
			if len(args) == 0 {
				return nil, c.Errf("allowedIPs directive requires at least one IP address or CIDR")
			}

			for _, ipString := range args {
				startIP, endIP, err := getIPRange(ipString)
				if err != nil {
					return nil, err
				}

				config.allowedIPs = append(config.allowedIPs, startIP)
				config.allowedIPs = append(config.allowedIPs, endIP)
			}

		default:
			return nil, c.Errf("unknown directive '%s'", directive)
		}
	}

	return config, nil
}

// validateConfig validates the parsed configuration for business logic rules.
// It checks that the mode is one of the supported values.
func validateConfig(config *parsedConfig) error {
	if config.mode == "" {
		return fmt.Errorf("mode is required")
	}

	if config.mode != ModeNFTLocal && config.mode != ModeNFTGateway {
		return fmt.Errorf("invalid mode '%s': must be '%s' or '%s'", config.mode, ModeNFTLocal, ModeNFTGateway)
	}

	return nil
}

// Returns the IP range end for given startIP with given subnet-mask bit count
func getIPRangeEnd(startIP net.IP, maskedBits uint) net.IP {
	startIPInt := big.NewInt(0)
	startIPInt.SetBytes(startIP)
	endIPInt := big.NewInt(1)
	endIPInt.Lsh(endIPInt, uint(len(startIP)*8)-maskedBits)
	endIPInt.Add(endIPInt, startIPInt)
	endIPBuffer := make([]byte, len(startIP))
	endIPBuffer = endIPInt.FillBytes(endIPBuffer)

	return net.IP(endIPBuffer)
}

// Parses given string and tries to determine the IP range it describes.
func getIPRange(str string) (net.IP, net.IP, error) {
	_, cidrNet, err := net.ParseCIDR(str)
	if err == nil {
		startIP := cidrNet.IP.To4()
		if startIP == nil {
			startIP = cidrNet.IP
		}

		prefixLen, _ := cidrNet.Mask.Size()

		return startIP, getIPRangeEnd(startIP, uint(prefixLen)), nil
	}

	ip := net.ParseIP(str)
	if ip != nil {
		startIP := ip.To4()
		prefixLen := uint(32)
		if startIP == nil {
			startIP = ip
			prefixLen = uint(128)
		}

		return startIP, getIPRangeEnd(startIP, prefixLen), nil
	}

	return nil, nil, fmt.Errorf("can't extract ip range from \"%s\", no CIDR or IP detected", str)
}

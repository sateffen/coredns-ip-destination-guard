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

const pluginName = "ipdestinationguard"

// Valid mode constants
const (
	ModeNFTLocal   Mode = "nft-local"
	ModeNFTGateway Mode = "nft-gateway"
	ModeNFTBoth    Mode = "nft-both"
)

type parsedIPRange struct {
	start   net.IP
	end     net.IP
	openEnd bool
}

type parsedConfig struct {
	mode              Mode
	allowedIPs        []parsedIPRange // Applied to all chains
	allowedLocalIPs   []parsedIPRange // Applied only to OUTPUT chain (nft-local)
	allowedGatewayIPs []parsedIPRange // Applied only to FORWARD chain (nft-gateway)
}

// define a named logger for nice logging.
var log = clog.NewWithPlugin(pluginName)

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	// First, skip the first token, which is the plugin name "ipdestinationguard"
	c.Next()

	// Second, parse configuration
	config, err := parseConfig(c)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	// Third, validate the parsed configuration
	err = validateConfig(config)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	// The create the manager based on the validated config
	var dgManager DestinationGuardManager
	dgManager, err = NewNFTablesManager(config)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	c.OnStartup(dgManager.Startup)
	c.OnShutdown(dgManager.Shutdown)

	// And finally, register plugin with the dnsserver
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return IPDestinationGuard{Next: next, DGManager: dgManager}
	})

	return nil
}

// parseConfig extracts configuration values from given the Caddy controller.
// It supports both single-line format and block format:
//   - Single-line: ipdestinationguard nft-local 1.2.3.4 5.6.7.0/24
//   - Block format: ipdestinationguard {
//     mode nft-local
//     allowedIPs 1.2.3.4 5.6.7.0/24
//     }
func parseConfig(c *caddy.Controller) (*parsedConfig, error) {
	config := &parsedConfig{
		mode:              "", // Empty string = invalid, will fail validation later
		allowedIPs:        make([]parsedIPRange, 0, 4),
		allowedLocalIPs:   make([]parsedIPRange, 0, 4),
		allowedGatewayIPs: make([]parsedIPRange, 0, 4),
	}

	// Single line format parsing
	allArgs := c.RemainingArgs()
	if len(allArgs) > 0 {
		config.mode = Mode(allArgs[0])

		for _, ipString := range allArgs[1:] {
			ipRange, err := getIPRange(ipString)
			if err != nil {
				return nil, err
			}

			config.allowedIPs = append(config.allowedIPs, *ipRange)
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
				ipRange, err := getIPRange(ipString)
				if err != nil {
					return nil, err
				}

				config.allowedIPs = append(config.allowedIPs, *ipRange)
			}

		case "allowedLocalIPs":
			args := c.RemainingArgs()
			if len(args) == 0 {
				return nil, c.Errf("allowedLocalIPs directive requires at least one IP address or CIDR")
			}

			for _, ipString := range args {
				ipRange, err := getIPRange(ipString)
				if err != nil {
					return nil, err
				}

				config.allowedLocalIPs = append(config.allowedLocalIPs, *ipRange)
			}

		case "allowedGatewayIPs":
			args := c.RemainingArgs()
			if len(args) == 0 {
				return nil, c.Errf("allowedGatewayIPs directive requires at least one IP address or CIDR")
			}

			for _, ipString := range args {
				ipRange, err := getIPRange(ipString)
				if err != nil {
					return nil, err
				}

				config.allowedGatewayIPs = append(config.allowedGatewayIPs, *ipRange)
			}

		default:
			return nil, c.Errf("unknown directive '%s'", directive)
		}
	}

	return config, nil
}

// validateConfig validates the parsed configuration for business logic rules.
// It checks that the mode is one of the supported values and warns about mismatched directives.
func validateConfig(config *parsedConfig) error {
	if config.mode == "" {
		return fmt.Errorf("mode is required")
	}

	if config.mode != ModeNFTLocal && config.mode != ModeNFTGateway && config.mode != ModeNFTBoth {
		return fmt.Errorf("invalid mode '%s': must be '%s', '%s', or '%s'", config.mode, ModeNFTLocal, ModeNFTGateway, ModeNFTBoth)
	}

	// Warn about mismatched directives (not an error, just informational)
	if config.mode == ModeNFTLocal && len(config.allowedGatewayIPs) > 0 {
		log.Warningf("allowedGatewayIPs configured but mode is nft-local; these IPs will be ignored")
	}

	if config.mode == ModeNFTGateway && len(config.allowedLocalIPs) > 0 {
		log.Warningf("allowedLocalIPs configured but mode is nft-gateway; these IPs will be ignored")
	}

	return nil
}

// Determines the actual parsed IP Range given startIP and masked bits
// The end IP is exclusive, like needed for nftables.
// openEnd means, that the end IP would overflow, therefore the interval is open end.
// WARNING: maskedBits has to be a valid value, this function does NOT validate this!
func innerGetIPRange(startIP net.IP, maskedBits uint) parsedIPRange {
	hostBits := uint(len(startIP)*8) - maskedBits

	startIPInt := big.NewInt(0)
	startIPInt.SetBytes(startIP)
	// set all hostbits to 0, to get the base address
	startIPInt.Lsh(startIPInt.Rsh(startIPInt, hostBits), hostBits)

	endIPInt := big.NewInt(1)
	endIPInt.Lsh(endIPInt, hostBits)
	endIPInt.Add(endIPInt, startIPInt)

	startIPBuffer := make([]byte, len(startIP))
	startIPBuffer = startIPInt.FillBytes(startIPBuffer)
	resultingIPRange := parsedIPRange{start: net.IP(startIPBuffer)}

	// if the end-addr needs more bytes than the start-addr, we overflow the IP range
	// so we tell the outer world there is no end-addr -> the range is open.
	if len(endIPInt.Bytes()) > len(startIP) {
		resultingIPRange.openEnd = true
	} else {
		endIPBuffer := make([]byte, len(startIP))
		endIPBuffer = endIPInt.FillBytes(endIPBuffer)
		resultingIPRange.end = net.IP(endIPBuffer)
		resultingIPRange.openEnd = false
	}

	return resultingIPRange
}

// Parses given string and tries to determine the IP range it describes.
func getIPRange(str string) (*parsedIPRange, error) {
	_, cidrNet, err := net.ParseCIDR(str)
	if err == nil {
		startIP := cidrNet.IP.To4()
		if startIP == nil {
			startIP = cidrNet.IP
		}

		prefixLen, _ := cidrNet.Mask.Size()

		if prefixLen == 0 {
			return nil, fmt.Errorf("received a CIDR with prefix length of 0, which is not supported")
		} else if prefixLen > len(startIP)*8 {
			return nil, fmt.Errorf("received a CIDR with too long prefix length of \"%d\"", prefixLen)
		}

		parsedRange := innerGetIPRange(startIP, uint(prefixLen))

		return &parsedRange, nil
	}

	ip := net.ParseIP(str)
	if ip != nil {
		startIP := ip.To4()
		prefixLen := uint(32)
		if startIP == nil {
			startIP = ip
			prefixLen = uint(128)
		}

		parsedRange := innerGetIPRange(startIP, prefixLen)

		return &parsedRange, nil
	}

	return nil, fmt.Errorf("can't extract ip range from \"%s\", no CIDR or IP detected", str)
}

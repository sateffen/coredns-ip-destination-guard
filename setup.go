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

type parsedCondig struct {
	mode       string
	allowedIPs []net.IP
}

// define a log target for nice logging later on.
var log = clog.NewWithPlugin("ipdestinationguard")

func init() { plugin.Register("ipdestinationguard", setup) }

func setup(c *caddy.Controller) error {
	c.Next() // returns "ipdestinationguard"

	allArgs := c.RemainingArgs()
	config := parsedCondig{
		mode:       "local",
		allowedIPs: make([]net.IP, 0, 4),
	}

	if len(allArgs) > 0 {
		config.mode = allArgs[0]

		for _, ipString := range allArgs[1:] {
			startIP, endIP, err := getIPRange(ipString)
			if err != nil {
				return plugin.Error("ipdestinationguard", err)
			}

			config.allowedIPs = append(config.allowedIPs, startIP)
			config.allowedIPs = append(config.allowedIPs, endIP)
		}
	}

	var dgManager DestinationGuardManager
	var err error

	if config.mode == "nft-local" || config.mode == "nft-gateway" {
		dgManager, err = NewNFTablesManager(config)
	} else {
		return plugin.Error("ipdestinationguard", fmt.Errorf("invalid first argument for \"mode\": \"%s\"", config.mode))
	}

	if err != nil {
		return plugin.Error("ipdestinationguard", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return IPDestinationGuard{Next: next, DGManager: dgManager}
	})

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

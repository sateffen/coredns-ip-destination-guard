package ipdestinationguard

import (
	"context"
	"net"

	"github.com/coredns/coredns/plugin"

	"github.com/miekg/dns"
)

// A basic interface that allows abstraction for different destination-guard-managers,
// like IPTables or BGP based ones
type DestinationGuardManager interface {
	AddRoutes(ips []net.IP, ttl uint32)
}

// The actual destination guard struct for this plugin.
// It has no real usecase, other than intercepting DNS requests and applying the ResponseParser to it.
type IPDestinationGuard struct {
	Next      plugin.Handler
	DGManager DestinationGuardManager
}

func (dg IPDestinationGuard) Name() string { return "ipdestinationguard" }
func (dg IPDestinationGuard) Ready() bool  { return true }

func (dg IPDestinationGuard) ServeDNS(ctx context.Context, writer dns.ResponseWriter, request *dns.Msg) (int, error) {
	return plugin.NextOrFailure(dg.Name(), dg.Next, ctx, NewResponseParser(writer, dg.DGManager), request)
}

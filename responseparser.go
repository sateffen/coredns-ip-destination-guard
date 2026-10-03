package ipdestinationguard

import (
	"net"

	"github.com/miekg/dns"
)

func NewResponseParser(writer dns.ResponseWriter, dgManager DestinationGuardManager) *ResponseParser {
	return &ResponseParser{
		ResponseWriter: writer,
		DGManager:      dgManager,
	}
}

type ResponseParser struct {
	dns.ResponseWriter
	DGManager DestinationGuardManager
}

func (parser *ResponseParser) WriteMsg(response *dns.Msg) error {
	var ips []net.IP
	var ttl uint32
	ttlSet := false

	// Note: In theory all entries of an RRSet should have the same TTL... unless they don't.
	// Usually an RRset is considered "malformed" if it has different TTLs set, but that's up to
	// the client to decide, soooo yeah, we have to deal with this properly, so the firewall doesn't
	// block the client. The RFC mentions that in such a case the lowest TTL is the leading one, so
	// we just follow that, see https://datatracker.ietf.org/doc/html/rfc2181#section-5.2

	for _, answer := range response.Answer {
		switch answer.Header().Rrtype {
		case dns.TypeA:
			dnsEntry := answer.(*dns.A)
			if ip := dnsEntry.A.To4(); ip != nil {
				ips = append(ips, ip)
			}
			if !ttlSet || dnsEntry.Hdr.Ttl < ttl {
				ttl = dnsEntry.Hdr.Ttl
				ttlSet = true
			}
		case dns.TypeAAAA:
			dnsEntry := answer.(*dns.AAAA)
			if ip := dnsEntry.AAAA.To16(); ip != nil {
				ips = append(ips, ip)
			}
			if !ttlSet || dnsEntry.Hdr.Ttl < ttl {
				ttl = dnsEntry.Hdr.Ttl
				ttlSet = true
			}
		}
		// other DNS types can't contain IPs, so we skip them
	}

	if len(ips) > 0 && ttlSet {
		parser.DGManager.AddRoutes(ips, ttl)
	}

	return parser.ResponseWriter.WriteMsg(response)
}

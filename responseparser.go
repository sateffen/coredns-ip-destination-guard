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

	for _, answer := range response.Answer {
		switch answer.Header().Rrtype {
		case dns.TypeA:
			dnsEntry := answer.(*dns.A)
			if ip := dnsEntry.A.To4(); ip != nil {
				ips = append(ips, ip)
			}
			ttl = dnsEntry.Hdr.Ttl
		case dns.TypeAAAA:
			dnsEntry := answer.(*dns.AAAA)
			if ip := dnsEntry.AAAA.To16(); ip != nil {
				ips = append(ips, ip)
			}
			ttl = dnsEntry.Hdr.Ttl
		}
		// other DNS types can't contain IPs, so we skip them
	}

	if len(ips) > 0 {
		parser.DGManager.AddRoutes(ips, ttl)
	}

	return parser.ResponseWriter.WriteMsg(response)
}

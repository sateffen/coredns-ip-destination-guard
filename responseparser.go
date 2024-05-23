package ipdestinationguard

import (
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
	for _, answer := range response.Answer {
		switch answer.Header().Rrtype {
		case dns.TypeA:
			dnsEntry := answer.(*dns.A)
			parser.DGManager.AddRoute(dnsEntry.A.To4(), dnsEntry.Hdr.Ttl)
		case dns.TypeAAAA:
			dnsEntry := answer.(*dns.AAAA)
			parser.DGManager.AddRoute(dnsEntry.AAAA.To16(), dnsEntry.Hdr.Ttl)
		}
		// other DNS types can't contain IPs, so we skip them
	}

	return parser.ResponseWriter.WriteMsg(response)
}

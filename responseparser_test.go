package ipdestinationguard

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// MockDestinationGuardManager is a mock implementation of DestinationGuardManager for testing
type MockDestinationGuardManager struct {
	capturedIPs  []net.IP
	capturedTTL  uint32
	callCount    int
	shouldVerify bool
}

func (m *MockDestinationGuardManager) AddRoutes(ips []net.IP, ttl uint32) {
	m.capturedIPs = append(m.capturedIPs, ips...)
	m.capturedTTL = ttl
	m.callCount++
}

// MockResponseWriter is a mock implementation of dns.ResponseWriter for testing
type MockResponseWriter struct {
	writtenMsg *dns.Msg
	writeError error
}

func (m *MockResponseWriter) LocalAddr() net.Addr                { return nil }
func (m *MockResponseWriter) RemoteAddr() net.Addr               { return nil }
func (m *MockResponseWriter) WriteMsg(msg *dns.Msg) error        { m.writtenMsg = msg; return m.writeError }
func (m *MockResponseWriter) Write([]byte) (int, error)          { return 0, nil }
func (m *MockResponseWriter) Close() error                       { return nil }
func (m *MockResponseWriter) TsigStatus() error                  { return nil }
func (m *MockResponseWriter) TsigTimersOnly(bool)                {}
func (m *MockResponseWriter) Hijack()                            {}

func TestWriteMsg_WithARecords(t *testing.T) {
	// Setup
	mockManager := &MockDestinationGuardManager{}
	mockWriter := &MockResponseWriter{}
	parser := NewResponseParser(mockWriter, mockManager)

	// Create DNS response with A record
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("192.168.1.1"),
		},
	}

	// Execute
	err := parser.WriteMsg(msg)

	// Assert
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if mockManager.callCount != 1 {
		t.Errorf("Expected AddRoutes to be called 1 time, got %d", mockManager.callCount)
	}

	if len(mockManager.capturedIPs) != 1 {
		t.Fatalf("Expected 1 IP, got %d", len(mockManager.capturedIPs))
	}

	expectedIP := net.ParseIP("192.168.1.1").To4()
	if !mockManager.capturedIPs[0].Equal(expectedIP) {
		t.Errorf("Expected IP %v, got %v", expectedIP, mockManager.capturedIPs[0])
	}

	if mockManager.capturedTTL != 300 {
		t.Errorf("Expected TTL 300, got %d", mockManager.capturedTTL)
	}

	if mockWriter.writtenMsg != msg {
		t.Error("Message was not written to underlying writer")
	}
}

func TestWriteMsg_WithAAAARecords(t *testing.T) {
	// Setup
	mockManager := &MockDestinationGuardManager{}
	mockWriter := &MockResponseWriter{}
	parser := NewResponseParser(mockWriter, mockManager)

	// Create DNS response with AAAA record
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    600,
			},
			AAAA: net.ParseIP("2001:db8::1"),
		},
	}

	// Execute
	err := parser.WriteMsg(msg)

	// Assert
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if mockManager.callCount != 1 {
		t.Errorf("Expected AddRoutes to be called 1 time, got %d", mockManager.callCount)
	}

	if len(mockManager.capturedIPs) != 1 {
		t.Fatalf("Expected 1 IP, got %d", len(mockManager.capturedIPs))
	}

	expectedIP := net.ParseIP("2001:db8::1").To16()
	if !mockManager.capturedIPs[0].Equal(expectedIP) {
		t.Errorf("Expected IP %v, got %v", expectedIP, mockManager.capturedIPs[0])
	}

	if mockManager.capturedTTL != 600 {
		t.Errorf("Expected TTL 600, got %d", mockManager.capturedTTL)
	}
}

func TestWriteMsg_WithMixedAandAAAA(t *testing.T) {
	// Setup
	mockManager := &MockDestinationGuardManager{}
	mockWriter := &MockResponseWriter{}
	parser := NewResponseParser(mockWriter, mockManager)

	// Create DNS response with both A and AAAA records
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("192.168.1.1"),
		},
		&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    600,
			},
			AAAA: net.ParseIP("2001:db8::1"),
		},
	}

	// Execute
	err := parser.WriteMsg(msg)

	// Assert
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if mockManager.callCount != 1 {
		t.Errorf("Expected AddRoutes to be called 1 time, got %d", mockManager.callCount)
	}

	if len(mockManager.capturedIPs) != 2 {
		t.Fatalf("Expected 2 IPs, got %d", len(mockManager.capturedIPs))
	}

	// Note: TTL is taken from last record (AAAA in this case)
	if mockManager.capturedTTL != 600 {
		t.Errorf("Expected TTL 600 (from AAAA record), got %d", mockManager.capturedTTL)
	}
}

func TestWriteMsg_WithMultipleARecords(t *testing.T) {
	// Setup
	mockManager := &MockDestinationGuardManager{}
	mockWriter := &MockResponseWriter{}
	parser := NewResponseParser(mockWriter, mockManager)

	// Create DNS response with multiple A records
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.168.1.1"),
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.168.1.2"),
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.168.1.3"),
		},
	}

	// Execute
	err := parser.WriteMsg(msg)

	// Assert
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(mockManager.capturedIPs) != 3 {
		t.Fatalf("Expected 3 IPs, got %d", len(mockManager.capturedIPs))
	}

	expectedIPs := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}
	for i, expectedIPStr := range expectedIPs {
		expectedIP := net.ParseIP(expectedIPStr).To4()
		if !mockManager.capturedIPs[i].Equal(expectedIP) {
			t.Errorf("Expected IP[%d] %v, got %v", i, expectedIP, mockManager.capturedIPs[i])
		}
	}
}

func TestWriteMsg_WithNoAnswers(t *testing.T) {
	// Setup
	mockManager := &MockDestinationGuardManager{}
	mockWriter := &MockResponseWriter{}
	parser := NewResponseParser(mockWriter, mockManager)

	// Create DNS response with no answers
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{}

	// Execute
	err := parser.WriteMsg(msg)

	// Assert
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if mockManager.callCount != 0 {
		t.Errorf("Expected AddRoutes to not be called, but was called %d times", mockManager.callCount)
	}

	if len(mockManager.capturedIPs) != 0 {
		t.Errorf("Expected no IPs captured, got %d", len(mockManager.capturedIPs))
	}
}

func TestWriteMsg_WithCNAMEOnly(t *testing.T) {
	// Setup
	mockManager := &MockDestinationGuardManager{}
	mockWriter := &MockResponseWriter{}
	parser := NewResponseParser(mockWriter, mockManager)

	// Create DNS response with only CNAME record (no A/AAAA)
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   "alias.example.com.",
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Target: "example.com.",
		},
	}

	// Execute
	err := parser.WriteMsg(msg)

	// Assert
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if mockManager.callCount != 0 {
		t.Errorf("Expected AddRoutes to not be called, but was called %d times", mockManager.callCount)
	}

	if len(mockManager.capturedIPs) != 0 {
		t.Errorf("Expected no IPs captured from CNAME, got %d", len(mockManager.capturedIPs))
	}
}

func TestWriteMsg_WithMixedRecordTypes(t *testing.T) {
	// Setup
	mockManager := &MockDestinationGuardManager{}
	mockWriter := &MockResponseWriter{}
	parser := NewResponseParser(mockWriter, mockManager)

	// Create DNS response with A record, CNAME, and MX record
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "alias.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: "example.com.",
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.168.1.1"),
		},
		&dns.MX{
			Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
			Preference: 10,
			Mx:         "mail.example.com.",
		},
	}

	// Execute
	err := parser.WriteMsg(msg)

	// Assert
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should only capture the A record, not CNAME or MX
	if len(mockManager.capturedIPs) != 1 {
		t.Fatalf("Expected 1 IP (from A record only), got %d", len(mockManager.capturedIPs))
	}

	expectedIP := net.ParseIP("192.168.1.1").To4()
	if !mockManager.capturedIPs[0].Equal(expectedIP) {
		t.Errorf("Expected IP %v, got %v", expectedIP, mockManager.capturedIPs[0])
	}
}

func TestWriteMsg_TTLHandling(t *testing.T) {
	tests := []struct {
		name        string
		ttl         uint32
		expectedTTL uint32
	}{
		{
			name:        "low TTL",
			ttl:         60,
			expectedTTL: 60,
		},
		{
			name:        "medium TTL",
			ttl:         3600,
			expectedTTL: 3600,
		},
		{
			name:        "high TTL",
			ttl:         86400,
			expectedTTL: 86400,
		},
		{
			name:        "zero TTL",
			ttl:         0,
			expectedTTL: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockManager := &MockDestinationGuardManager{}
			mockWriter := &MockResponseWriter{}
			parser := NewResponseParser(mockWriter, mockManager)

			msg := new(dns.Msg)
			msg.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    tt.ttl,
					},
					A: net.ParseIP("192.168.1.1"),
				},
			}

			err := parser.WriteMsg(msg)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if mockManager.capturedTTL != tt.expectedTTL {
				t.Errorf("Expected TTL %d, got %d", tt.expectedTTL, mockManager.capturedTTL)
			}
		})
	}
}

func TestWriteMsg_NilAnswerSection(t *testing.T) {
	// Setup
	mockManager := &MockDestinationGuardManager{}
	mockWriter := &MockResponseWriter{}
	parser := NewResponseParser(mockWriter, mockManager)

	// Create DNS response with nil answer section
	msg := new(dns.Msg)
	msg.Answer = nil

	// Execute
	err := parser.WriteMsg(msg)

	// Assert
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if mockManager.callCount != 0 {
		t.Errorf("Expected AddRoutes to not be called, but was called %d times", mockManager.callCount)
	}
}

func TestNewResponseParser(t *testing.T) {
	// Setup
	mockManager := &MockDestinationGuardManager{}
	mockWriter := &MockResponseWriter{}

	// Execute
	parser := NewResponseParser(mockWriter, mockManager)

	// Assert
	if parser == nil {
		t.Fatal("Expected non-nil parser")
	}

	if parser.ResponseWriter != mockWriter {
		t.Error("ResponseWriter not set correctly")
	}

	if parser.DGManager != mockManager {
		t.Error("DGManager not set correctly")
	}
}

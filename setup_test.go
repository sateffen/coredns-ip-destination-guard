package ipdestinationguard

import (
	"net"
	"testing"
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

package publicfetch

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsPublicUnicast(t *testing.T) {
	tests := []struct {
		class string
		ip    string
		want  bool
	}{
		// Global unicast, accepted.
		{"public IPv4", "8.8.8.8", true},
		{"public IPv4", "1.1.1.1", true},
		{"public IPv4", "93.184.215.14", true},
		{"public IPv4 at the top of unicast", "223.255.255.255", true},
		{"public IPv6", "2606:4700:4700::1111", true},
		{"public IPv6", "2a00:1450:4001:82a::200e", true},
		{"public IPv6 right after 2001::/23", "2001:200::1", true},
		{"public IPv6 next to 3fff::/20", "3fff:1000::1", true},

		// Boundaries of refused blocks, accepted.
		{"below carrier-grade NAT", "100.63.255.255", true},
		{"above carrier-grade NAT", "100.128.0.0", true},
		{"below 172.16.0.0/12", "172.15.255.255", true},
		{"above 172.16.0.0/12", "172.32.0.0", true},
		{"below benchmarking", "198.17.255.255", true},
		{"above benchmarking", "198.20.0.0", true},
		{"next to 192.0.2.0/24", "192.0.3.1", true},

		// Private.
		{"private", "10.0.0.1", false},
		{"private", "172.16.5.4", false},
		{"private", "172.31.255.255", false},
		{"private", "192.168.1.1", false},
		// Loopback.
		{"loopback", "127.0.0.1", false},
		{"loopback", "127.255.255.254", false},
		{"loopback", "::1", false},
		// Link-local, including the cloud metadata address.
		{"link-local", "169.254.169.254", false},
		{"link-local", "fe80::1", false},
		{"link-local with zone", "fe80::1%eth0", false},
		// Carrier-grade NAT.
		{"carrier-grade NAT", "100.64.0.1", false},
		{"carrier-grade NAT", "100.127.255.255", false},
		// Benchmarking.
		{"benchmarking", "198.18.0.1", false},
		{"benchmarking", "198.19.255.255", false},
		{"benchmarking", "2001:2::1", false},
		// Documentation.
		{"documentation", "192.0.2.1", false},
		{"documentation", "198.51.100.1", false},
		{"documentation", "203.0.113.1", false},
		{"documentation", "2001:db8::1", false},
		{"documentation", "3fff::1", false},
		// Multicast.
		{"multicast", "224.0.0.1", false},
		{"multicast", "239.255.255.250", false},
		{"multicast", "ff02::1", false},
		{"multicast", "ff0e::1", false},
		// Reserved.
		{"reserved", "240.0.0.1", false},
		{"limited broadcast", "255.255.255.255", false},
		{"this network", "0.0.0.0", false},
		{"this network", "0.1.2.3", false},
		{"unspecified", "::", false},
		{"reserved outside 2000::/3", "1fff:ffff::1", false},
		{"reserved outside 2000::/3", "4000::1", false},
		{"deprecated site-local", "fec0::1", false},
		{"deprecated IPv4-compatible", "::a00:1", false},
		// Unique-local.
		{"unique-local", "fd00::1", false},
		{"unique-local", "fc00::1", false},
		// The remaining special-purpose blocks.
		{"IETF protocol assignments", "192.0.0.1", false},
		{"PCP anycast", "192.0.0.9", false},
		{"NAT64 discovery", "192.0.0.170", false},
		{"AS112-v4", "192.31.196.1", false},
		{"AMT", "192.52.193.1", false},
		{"deprecated 6to4 relay anycast", "192.88.99.1", false},
		{"6a44 relay anycast", "192.88.99.2", false},
		{"direct delegation AS112", "192.175.48.1", false},
		{"Teredo", "2001::1", false},
		{"PCP anycast", "2001:1::1", false},
		{"AMT", "2001:3::1", false},
		{"AS112-v6", "2001:4:112::1", false},
		{"ORCHIDv2", "2001:20::1", false},
		{"DRIP entity tags", "2001:30::1", false},
		{"6to4", "2002::1", false},
		{"6to4 wrapping a public IPv4", "2002:808:808::1", false},
		{"direct delegation AS112 (IPv6)", "2620:4f:8000::1", false},
		{"discard-only", "100::1", false},
		{"dummy IPv6 prefix", "100:0:0:1::1", false},
		{"SRv6 SIDs", "5f00::1", false},

		// IPv4-mapped IPv6: judged by the embedded IPv4 address.
		{"IPv4-mapped private", "::ffff:10.0.0.1", false},
		{"IPv4-mapped loopback", "::ffff:127.0.0.1", false},
		{"IPv4-mapped link-local", "::ffff:169.254.169.254", false},
		{"IPv4-mapped public", "::ffff:8.8.8.8", true},
		// NAT64 well-known prefix: judged by the embedded IPv4 address.
		{"translated link-local metadata address", "64:ff9b::a9fe:a9fe", false},
		{"translated loopback", "64:ff9b::7f00:1", false},
		{"translated private", "64:ff9b::a00:1", false},
		{"translated carrier-grade NAT", "64:ff9b::6440:1", false},
		{"translated public", "64:ff9b::808:808", true},
		{"translated public, dotted form", "64:ff9b::1.1.1.1", true},
		// NAT64 local-use prefix: refused whatever it embeds.
		{"local-use translation of a public address", "64:ff9b:1::808:808", false},
	}
	for _, tt := range tests {
		t.Run(tt.class+" "+tt.ip, func(t *testing.T) {
			ip, err := netip.ParseAddr(tt.ip)
			require.NoError(t, err)
			assert.Equal(t, tt.want, IsPublicUnicast(ip))
		})
	}

	t.Run("invalid address", func(t *testing.T) {
		assert.False(t, IsPublicUnicast(netip.Addr{}))
	})
}

func TestCheckAddress(t *testing.T) {
	tests := []struct {
		addr    string
		wantErr bool
	}{
		{"8.8.8.8:443", false},
		{"[2606:4700:4700::1111]:443", false},
		{"[64:ff9b::808:808]:443", false},
		{"8.8.8.8:80", true},
		{"8.8.8.8:8443", true},
		{"8.8.8.8:0", true},
		{"[2606:4700:4700::1111]:8443", true},
		{"10.0.0.1:443", true},
		{"[fd00::1]:443", true},
		{"[64:ff9b::a9fe:a9fe]:443", true},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			err := CheckAddress(netip.MustParseAddrPort(tt.addr))
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrDenied)
				return
			}
			assert.NoError(t, err)
		})
	}
}

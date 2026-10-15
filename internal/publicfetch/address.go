package publicfetch

import (
	"fmt"
	"net/netip"
)

// Port is the only port a connection is made to: the standard port of https.
const Port = 443

// CheckAddress reports whether a connection to addr may be made. It returns nil when the port is
// Port and the address is a public unicast address (IsPublicUnicast), and an error wrapping
// ErrDenied otherwise. It is a pure function of addr.
func CheckAddress(addr netip.AddrPort) error {
	if addr.Port() != Port {
		return fmt.Errorf("%w: port %d is not %d", ErrDenied, addr.Port(), Port)
	}
	if !IsPublicUnicast(addr.Addr()) {
		return fmt.Errorf("%w: %s is not a public unicast address", ErrDenied, addr.Addr())
	}
	return nil
}

// IsPublicUnicast reports whether ip is an ordinary public unicast address, the only kind a
// document named by a caller may be fetched from.
//
// The rule follows the IANA registries (checked 2026-10-15):
//
//   - IPv4 Special-Purpose Address Registry
//     https://www.iana.org/assignments/iana-ipv4-special-registry/
//   - IPv6 Special-Purpose Address Registry
//     https://www.iana.org/assignments/iana-ipv6-special-registry/
//   - IPv4 Address Space Registry (multicast) and IPv6 Address Space Registry (global unicast)
//     https://www.iana.org/assignments/ipv4-address-space/
//     https://www.iana.org/assignments/ipv6-address-space/
//
// Every block of the special-purpose registries is refused, whatever its "globally reachable"
// flag: the blocks flagged reachable are anycast relays, sink servers and identifiers, none of
// which serves a document, so refusing them costs nothing and keeps the rule simple to check
// against the registry. IPv4 multicast is refused too. An IPv6 address counts only inside the
// global unicast space 2000::/3; everything outside it is reserved, unique-local, link-local or
// multicast.
//
// Two IPv6 forms carry an IPv4 address and are judged by it instead: an IPv4-mapped address
// (::ffff:0:0/96, RFC 4291) and an address translated under the NAT64 well-known prefix
// (64:ff9b::/96, RFC 6052), so a host reached through NAT64 is accepted exactly when its IPv4
// address would be, and a translated link-local or private address is refused. The local-use
// translation prefix (64:ff9b:1::/48, RFC 8215) is operator-defined, so it is refused.
//
// An address with a zone is refused: only link-local and other non-global addresses carry one.
func IsPublicUnicast(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if ip.Is4() {
		return isPublicIPv4(ip)
	}
	if nat64WellKnownPrefix.Contains(ip) {
		return isPublicIPv4(embeddedIPv4(ip))
	}
	return isPublicIPv6(ip)
}

func isPublicIPv4(ip netip.Addr) bool {
	return !containedIn(refusedIPv4, ip)
}

func isPublicIPv6(ip netip.Addr) bool {
	return ipv6GlobalUnicast.Contains(ip) && !containedIn(refusedIPv6, ip)
}

// embeddedIPv4 returns the IPv4 address in the last 32 bits of a /96 translation prefix
// (RFC 6052, section 2.2).
func embeddedIPv4(ip netip.Addr) netip.Addr {
	b := ip.As16()
	return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
}

func containedIn(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

var (
	// nat64WellKnownPrefix is decoded rather than refused (IPv6 special-purpose registry, RFC 6052).
	nat64WellKnownPrefix = netip.MustParsePrefix("64:ff9b::/96")
	// ipv6GlobalUnicast is the only IPv6 space IANA assigns unicast addresses from.
	ipv6GlobalUnicast = netip.MustParsePrefix("2000::/3")
)

// refusedIPv4 is every block of the IPv4 special-purpose registry, plus multicast. More specific
// registry entries inside a listed block (0.0.0.0/32 in 0.0.0.0/8; 192.0.0.0/29, 192.0.0.8/32,
// 192.0.0.9/32, 192.0.0.10/32, 192.0.0.170/32 and 192.0.0.171/32 in 192.0.0.0/24; 192.88.99.2/32
// in 192.88.99.0/24) are covered by it.
var refusedIPv4 = mustParsePrefixes(
	"0.0.0.0/8",          // "This network", RFC 791
	"10.0.0.0/8",         // Private-Use, RFC 1918
	"100.64.0.0/10",      // Shared Address Space (carrier-grade NAT), RFC 6598
	"127.0.0.0/8",        // Loopback, RFC 1122
	"169.254.0.0/16",     // Link Local, RFC 3927 (includes cloud metadata endpoints)
	"172.16.0.0/12",      // Private-Use, RFC 1918
	"192.0.0.0/24",       // IETF Protocol Assignments, RFC 6890
	"192.0.2.0/24",       // Documentation (TEST-NET-1), RFC 5737
	"192.31.196.0/24",    // AS112-v4, RFC 7535
	"192.52.193.0/24",    // AMT, RFC 7450
	"192.88.99.0/24",     // Deprecated (6to4 Relay Anycast), RFC 7526
	"192.168.0.0/16",     // Private-Use, RFC 1918
	"192.175.48.0/24",    // Direct Delegation AS112 Service, RFC 7534
	"198.18.0.0/15",      // Benchmarking, RFC 2544
	"198.51.100.0/24",    // Documentation (TEST-NET-2), RFC 5737
	"203.0.113.0/24",     // Documentation (TEST-NET-3), RFC 5737
	"224.0.0.0/4",        // Multicast, IPv4 address space registry
	"240.0.0.0/4",        // Reserved, RFC 1112
	"255.255.255.255/32", // Limited Broadcast, RFC 919 (inside 240.0.0.0/4, listed as in the registry)
)

// refusedIPv6 is every block of the IPv6 special-purpose registry except the two that are decoded
// (::ffff:0:0/96 and 64:ff9b::/96). Only the blocks inside 2000::/3 change the result, as
// isPublicIPv6 refuses everything outside it; the others are listed so the table can be compared
// with the registry line by line. More specific entries inside 2001::/23 (2001::/32, 2001:1::1/128,
// 2001:1::2/128, 2001:1::3/128, 2001:2::/48, 2001:3::/32, 2001:4:112::/48, 2001:10::/28,
// 2001:20::/28, 2001:30::/28) are covered by it.
var refusedIPv6 = mustParsePrefixes(
	"::1/128",           // Loopback Address, RFC 4291
	"::/128",            // Unspecified Address, RFC 4291
	"64:ff9b:1::/48",    // IPv4-IPv6 Translation, local use, RFC 8215
	"100::/64",          // Discard-Only Address Block, RFC 6666
	"100:0:0:1::/64",    // Dummy IPv6 Prefix, RFC 9780
	"2001::/23",         // IETF Protocol Assignments, RFC 2928
	"2001:db8::/32",     // Documentation, RFC 3849
	"2002::/16",         // 6to4, RFC 3056
	"2620:4f:8000::/48", // Direct Delegation AS112 Service, RFC 7534
	"3fff::/20",         // Documentation, RFC 9637
	"5f00::/16",         // Segment Routing (SRv6) SIDs, RFC 9602
	"fc00::/7",          // Unique-Local, RFC 4193
	"fe80::/10",         // Link-Local Unicast, RFC 4291
)

func mustParsePrefixes(prefixes ...string) []netip.Prefix {
	parsed := make([]netip.Prefix, len(prefixes))
	for i, prefix := range prefixes {
		parsed[i] = netip.MustParsePrefix(prefix)
	}
	return parsed
}

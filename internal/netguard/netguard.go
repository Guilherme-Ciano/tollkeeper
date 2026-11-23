package netguard

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

var ErrBlockedAddress = errors.New("address blocked by egress policy")

func restrictedPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
		netip.MustParsePrefix("100::/64"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
}

func IsRestrictedIP(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	ip := addr.Unmap()
	if ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		ip.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range restrictedPrefixes() {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func CheckAddrPort(address string) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: invalid address %q", ErrBlockedAddress, address)
	}
	if IsRestrictedIP(ap.Addr()) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, ap.Addr())
	}
	return nil
}

func Control(_, address string, _ syscall.RawConn) error {
	return CheckAddrPort(address)
}

func Dialer(timeout, keepAlive time.Duration, blockPrivate bool) *net.Dialer {
	d := &net.Dialer{Timeout: timeout, KeepAlive: keepAlive}
	if blockPrivate {
		d.Control = Control
	}
	return d
}

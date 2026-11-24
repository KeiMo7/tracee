package ipreputation

import (
	"fmt"
	"net/netip"
	"strings"
)

// normalization maps the many textual spellings of an address onto the single
// canonical form the store indexes. The canonical key for an exact address is
// the plain IP (no brackets, no port, no zone, IPv4-mapped IPv6 folded to
// IPv4). The canonical form for a network is its masked CIDR.

// keyKind distinguishes an exact-address key from a network key so the two
// namespaces never collide ("10.0.0.0/8" is not a valid address anyway, but
// keeping the kind explicit makes lookups and deletions unambiguous).
type keyKind int

const (
	keyAddr keyKind = iota
	keyPrefix
)

// parsedKey is the normalized form of a written or queried key.
type parsedKey struct {
	kind   keyKind
	addr   netip.Addr   // valid when kind == keyAddr
	prefix netip.Prefix // valid when kind == keyPrefix
	// text is the canonical string: addr.String() or prefix.String().
	text string
}

func (k parsedKey) String() string { return k.text }

// indexPrefix is the prefix an exact address or a network is stored under.
// Exact addresses live at their full-length prefix (/32 or /128), which makes
// longest-prefix matching uniform for both kinds of entry.
func (k parsedKey) indexPrefix() netip.Prefix {
	if k.kind == keyPrefix {
		return k.prefix
	}
	return netip.PrefixFrom(k.addr, k.addr.BitLen())
}

// normalizeKey turns user input into a canonical key.
//
// Accepted address forms (all normalized to the same canonical key):
//   - plain IPv4/IPv6:            "1.2.3.4", "2001:0db8::1"
//   - leading-zero IPv4 octets:   "010.001.002.003"
//   - IPv4-mapped IPv6:           "::ffff:1.2.3.4"
//   - bracketed:                  "[2001:db8::1]"
//   - address with a port:        "1.2.3.4:443", "[2001:db8::1]:443"
//   - zoned IPv6:                 "fe80::1%eth0" (zone is dropped)
//
// Accepted network forms:
//   - IPv4/IPv6 CIDR:             "10.0.0.0/8", "2001:db8::/32"
//   - host bits set is rejected:  "10.1.2.3/8" (use the masked form)
func normalizeKey(raw string) (parsedKey, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return parsedKey{}, fmt.Errorf("empty address")
	}

	if strings.Contains(s, "/") {
		return normalizePrefix(s)
	}

	addr, err := parseAddrLoose(s)
	if err != nil {
		return parsedKey{}, err
	}

	return parsedKey{
		kind: keyAddr,
		addr: addr,
		text: addr.String(),
	}, nil
}

// normalizePrefix validates a CIDR string and masks it. It rejects prefixes
// with host bits set so a typo cannot silently widen what the feed meant.
func normalizePrefix(s string) (parsedKey, error) {
	// Strip a zone from the address part if present (fe80::1%eth0/64).
	if i := strings.IndexByte(s, '%'); i >= 0 {
		slash := strings.IndexByte(s, '/')
		if slash > i {
			s = s[:i] + s[slash:]
		}
	}

	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		// Fall back to a looser parse: strip brackets and ports before the
		// slash (e.g. "[2001:db8::1]/32").
		if p2, ok := parsePrefixLoose(s); ok {
			prefix = p2
		} else {
			return parsedKey{}, fmt.Errorf("invalid network %q: %w", s, err)
		}
	}

	if prefix.Addr().Zone() != "" {
		prefix = netip.PrefixFrom(prefix.Addr().WithZone(""), prefix.Bits())
	}

	// Fold IPv4-mapped IPv6 prefixes onto IPv4 when they cover exactly the
	// mapped /96..128 range, so "::ffff:10.0.0.0/104" and "10.0.0.0/8" name the
	// same network. Anything shorter than /96 is a genuine IPv6 network.
	if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
		addr := prefix.Addr().Unmap()
		prefix = netip.PrefixFrom(addr, prefix.Bits()-96)
	}

	masked := prefix.Masked()
	if masked != prefix {
		return parsedKey{}, fmt.Errorf(
			"invalid network %q: host bits must be zero (did you mean %q?)",
			s, masked.String())
	}

	return parsedKey{
		kind:   keyPrefix,
		prefix: masked,
		text:   masked.String(),
	}, nil
}

// parseAddrLoose accepts the textual variations listed on normalizeKey and
// returns an unmapped, zone-free address.
func parseAddrLoose(s string) (netip.Addr, error) {
	// Bracketed address, possibly followed by :port.
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return netip.Addr{}, fmt.Errorf("invalid address %q: missing ']'", s)
		}
		inner := s[1:end]
		rest := s[end+1:]
		if rest != "" && !isPortSuffix(rest) {
			return netip.Addr{}, fmt.Errorf("invalid address %q: unexpected %q after ']'", s, rest)
		}
		return finishAddr(inner)
	}

	// Bare address first: this is the only form where a colon is harmless
	// (IPv6 addresses contain colons).
	if addr, err := netip.ParseAddr(s); err == nil {
		return finishAddr(addr.String())
	}

	// Leading-zero IPv4 octets: netip rejects them, but feeds emit them.
	if addr, ok := parseLegacyIPv4(s); ok {
		return finishAddr(addr.String())
	}

	// Address with a port. Only an IPv4 address can carry a port without
	// brackets; an unbracketed IPv6 with a port is ambiguous and rejected.
	if host, port, found := strings.Cut(s, ":"); found && port != "" && isNumericPort(port) {
		if addr, err := netip.ParseAddr(host); err == nil && addr.Is4() {
			return finishAddr(addr.String())
		}
		if addr, ok := parseLegacyIPv4(host); ok && addr.Is4() {
			return finishAddr(addr.String())
		}
	}

	return netip.Addr{}, fmt.Errorf("invalid address %q", s)
}

// parsePrefixLoose handles bracketed CIDR spellings such as "[2001:db8::1]/32".
func parsePrefixLoose(s string) (netip.Prefix, bool) {
	slash := strings.LastIndexByte(s, '/')
	if slash < 0 {
		return netip.Prefix{}, false
	}
	addrPart, bitsPart := s[:slash], s[slash+1:]
	if strings.HasPrefix(addrPart, "[") && strings.HasSuffix(addrPart, "]") {
		addrPart = addrPart[1 : len(addrPart)-1]
	}
	full := addrPart + "/" + bitsPart
	prefix, err := netip.ParsePrefix(full)
	if err != nil {
		return netip.Prefix{}, false
	}
	return prefix, true
}

// finishAddr canonicalizes a parsed address: drop the zone and fold
// IPv4-mapped IPv6 onto plain IPv4.
func finishAddr(s string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		if addr4, ok := parseLegacyIPv4(s); ok {
			return addr4, nil
		}
		return netip.Addr{}, fmt.Errorf("invalid address %q: %w", s, err)
	}
	if addr.Zone() != "" {
		addr = addr.WithZone("")
	}
	return addr.Unmap(), nil
}

// parseLegacyIPv4 parses dotted-quad IPv4 allowing leading zeros in octets.
func parseLegacyIPv4(s string) (netip.Addr, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return netip.Addr{}, false
	}
	var octets [4]byte
	for i, p := range parts {
		if p == "" || len(p) > 3 {
			return netip.Addr{}, false
		}
		v := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return netip.Addr{}, false
			}
			v = v*10 + int(c-'0')
		}
		if v > 255 {
			return netip.Addr{}, false
		}
		octets[i] = byte(v)
	}
	return netip.AddrFrom4(octets), true
}

// isPortSuffix reports whether rest is ":<digits>".
func isPortSuffix(rest string) bool {
	if !strings.HasPrefix(rest, ":") {
		return false
	}
	return isNumericPort(rest[1:])
}

func isNumericPort(s string) bool {
	if s == "" || len(s) > 5 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

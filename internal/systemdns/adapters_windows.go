//go:build windows

package systemdns

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsAdapterBufferSize is the first guess at the size of the adapter
// table. Microsoft's own guidance is to start at 15 KB, which covers a typical
// host in a single call.
const windowsAdapterBufferSize = 15 * 1024

// windowsAdapterAttempts bounds the resize loop. GetAdaptersAddresses reports
// the size it needs, but an adapter appearing between two calls can make that
// answer stale, so the loop retries — without letting a host whose adapter
// table keeps changing spin here for the whole run.
const windowsAdapterAttempts = 4

// platformWindowsAdapters reads the resolver configuration through
// GetAdaptersAddresses. This is the same source the Windows resolver itself
// uses, and unlike shelling out to Get-DnsClientServerAddress it needs no
// PowerShell and parses no human-readable output. It only reads.
func platformWindowsAdapters() ([]windowsAdapter, error) {
	// Unicast, anycast and multicast addresses are the bulk of the table and
	// none of them are resolvers; skipping them keeps the buffer small. The
	// DNS server and friendly name lists must not be skipped.
	const flags = windows.GAA_FLAG_SKIP_UNICAST |
		windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST

	size := uint32(windowsAdapterBufferSize)
	for attempt := 0; attempt < windowsAdapterAttempts; attempt++ {
		buffer := make([]byte, size)
		table := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, table, &size)
		switch {
		case err == nil:
			return collectWindowsAdapters(table), nil
		case errors.Is(err, windows.ERROR_BUFFER_OVERFLOW):
			// size now holds the length the call actually needs.
			continue
		case errors.Is(err, windows.ERROR_NO_DATA):
			// A host with no configured addresses at all. Discover turns an
			// empty result into its own "no system nameservers" message,
			// which says more than a raw Windows error code would.
			return nil, nil
		default:
			return nil, fmt.Errorf("read Windows adapter addresses: %w", err)
		}
	}
	return nil, fmt.Errorf("read Windows adapter addresses: table kept growing after %d attempts", windowsAdapterAttempts)
}

// collectWindowsAdapters walks the linked list the API returns. Adapters that
// are not up are skipped because their configured resolvers are not the ones
// the host is using, and the software loopback adapter is skipped because it
// carries no resolver configuration of its own.
func collectWindowsAdapters(table *windows.IpAdapterAddresses) []windowsAdapter {
	var adapters []windowsAdapter
	for entry := table; entry != nil; entry = entry.Next {
		if entry.OperStatus != windows.IfOperStatusUp || entry.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		var nameservers []string
		for server := entry.FirstDnsServerAddress; server != nil; server = server.Next {
			if address, ok := windowsDNSAddress(&server.Address, entry.Ipv6IfIndex); ok {
				nameservers = append(nameservers, address)
			}
		}
		if len(nameservers) == 0 {
			continue
		}
		adapters = append(adapters, windowsAdapter{
			Index:       int(entry.IfIndex),
			Name:        windows.UTF16PtrToString(entry.FriendlyName),
			Nameservers: nameservers,
		})
	}
	return adapters
}

// windowsDNSAddress renders one configured nameserver. A link-local IPv6
// resolver is reachable only through the adapter that advertised it, so its
// interface index is carried through as the address zone; without the zone the
// dial fails on any host whose router advertises fe80::1.
func windowsDNSAddress(socket *windows.SocketAddress, adapterIndex uint32) (string, bool) {
	if socket.Sockaddr == nil {
		return "", false
	}
	address, ok := netip.AddrFromSlice(socket.IP())
	if !ok {
		return "", false
	}
	address = address.Unmap()
	if address.Is6() && address.IsLinkLocalUnicast() {
		zone := windowsSocketZone(socket)
		if zone == 0 {
			zone = adapterIndex
		}
		if zone != 0 {
			address = address.WithZone(strconv.FormatUint(uint64(zone), 10))
		}
	}
	return address.String(), true
}

// windowsSocketZone reads the scope ID the API attached to an IPv6 nameserver.
// It is preferred over the adapter's own IPv6 index because a resolver learned
// over one interface can be scoped to another.
func windowsSocketZone(socket *windows.SocketAddress) uint32 {
	if socket.Sockaddr == nil ||
		uintptr(socket.SockaddrLength) < unsafe.Sizeof(windows.RawSockaddrInet6{}) ||
		socket.Sockaddr.Addr.Family != windows.AF_INET6 {
		return 0
	}
	return (*windows.RawSockaddrInet6)(unsafe.Pointer(socket.Sockaddr)).Scope_id
}

package socks5

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Authentication METHODs described in RFC 1928, section 3.
const (
	noAuthRequired   byte = 0
	passwordAuth     byte = 2
	noAcceptableAuth byte = 255
)

// passwordAuthVersion is the auth version byte described in RFC 1929.
const passwordAuthVersion = 1

// socks5Version is the byte that represents the SOCKS version
// in requests.
const socks5Version byte = 5

// commandType are the bytes sent in SOCKS5 packets
// that represent the kind of connection the client needs.
type commandType byte

// The set of valid SOCKS5 commands as described in RFC 1928.
const (
	connect      commandType = 1
	bind         commandType = 2
	udpAssociate commandType = 3
)

// addrType are the bytes sent in SOCKS5 packets
// that represent particular address types.
type addrType byte

// The set of valid SOCKS5 address types as defined in RFC 1928.
const (
	ipv4       addrType = 1
	domainName addrType = 3
	ipv6       addrType = 4
)

// replyCode are the bytes sent in SOCKS5 packets
// that represent replies from the server to a client
// request.
type replyCode byte

// The set of valid SOCKS5 reply types as per the RFC 1928.
const (
	success              replyCode = 0
	generalFailure       replyCode = 1
	connectionNotAllowed replyCode = 2
	networkUnreachable   replyCode = 3
	hostUnreachable      replyCode = 4
	connectionRefused    replyCode = 5
	ttlExpired           replyCode = 6
	commandNotSupported  replyCode = 7
	addrTypeNotSupported replyCode = 8
)

// response contains the contents of
// a response packet sent from the proxy
// to the client.
type response struct {
	reply        replyCode
	bindAddrType addrType
	bindAddr     string
	bindPort     uint16
}

// marshal converts a SOCKS5Response struct into
// a packet. If res.reply == Success, it may throw an error on
// receiving an invalid bind address. Otherwise, it will not throw.
func (res *response) marshal() ([]byte, error) {
	pkt := make([]byte, 4)
	pkt[0] = socks5Version
	pkt[1] = byte(res.reply)
	pkt[2] = 0 // null reserved byte
	pkt[3] = byte(res.bindAddrType)

	if res.reply != success {
		return pkt, nil
	}

	var addr []byte
	switch res.bindAddrType {
	case ipv4:
		addr = net.ParseIP(res.bindAddr).To4()
		if addr == nil {
			return nil, fmt.Errorf("invalid IPv4 address for binding")
		}
	case domainName:
		if len(res.bindAddr) > 255 {
			return nil, fmt.Errorf("invalid domain name for binding")
		}
		addr = make([]byte, 0, len(res.bindAddr)+1)
		addr = append(addr, byte(len(res.bindAddr)))
		addr = append(addr, []byte(res.bindAddr)...)
	case ipv6:
		addr = net.ParseIP(res.bindAddr).To16()
		if addr == nil {
			return nil, fmt.Errorf("invalid IPv6 address for binding")
		}
	default:
		return nil, fmt.Errorf("unsupported address type")
	}

	pkt = append(pkt, addr...)
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(res.bindPort))

	return pkt, nil
}

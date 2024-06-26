package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/panjf2000/gnet/v2"
	"github.com/panjf2000/gnet/v2/pkg/pool/byteslice"
	"github.com/samber/lo"

	"github.com/shanexu/gnet-socks5/internel/logging"
)

var (
	ErrIncompatibleSocksVersion = errors.New("incompatible socks version")
	ErrNoAcceptableAuth         = errors.New("no acceptable auth")
	ErrBadSocksAuthVersion      = errors.New("bad socks auth version")
	ErrAuthFailed               = errors.New("auth failed")
	ErrUnsupportedCommand       = errors.New("unsupported command")
)

type GNetServer struct {
	gnet.BuiltinEventEngine
	eng      gnet.Engine
	addr     string
	username string
	password string
	cli      *gnet.Client
}

type codecState interface {
	onTraffic(conn gnet.Conn) (codecState, error)
}

type initState struct {
}

func (s initState) onTraffic(conn gnet.Conn) (codecState, error) {
	if conn.InboundBuffered() < 2 {
		return s, nil
	}
	hdr := byteslice.Get(2)
	defer byteslice.Put(hdr)
	_, err := io.ReadFull(conn, hdr)
	if err != nil {
		return nil, err
	}
	if hdr[0] != socks5Version {
		return nil, ErrIncompatibleSocksVersion
	}
	return &readAuthMethodsState{NMethods: int(hdr[1])}, nil
}

var _initState codecState = initState{}

type readAuthMethodsState struct {
	NMethods int
}

func (s *readAuthMethodsState) onTraffic(conn gnet.Conn) (codecState, error) {
	if conn.InboundBuffered() < s.NMethods {
		return s, nil
	}
	co := conn.Context().(*codec)
	methods := byteslice.Get(s.NMethods)
	defer byteslice.Put(methods)
	_, err := io.ReadFull(conn, methods)
	if err != nil {
		return nil, err
	}
	for _, m := range methods {
		if m == co.authMethod {
			if co.authMethod == passwordAuth {
				conn.Write([]byte{socks5Version, co.authMethod})
				return _readULenState, nil
			}
			if co.authMethod == noAuthRequired {
				conn.Write([]byte{socks5Version, co.authMethod})
				return _authedState, nil
			}
		}
	}
	conn.Write([]byte{socks5Version, noAcceptableAuth})
	return nil, ErrNoAcceptableAuth
}

var _ codecState = (*readAuthMethodsState)(nil)

type readULenState struct {
}

func (s readULenState) onTraffic(conn gnet.Conn) (codecState, error) {
	if conn.InboundBuffered() < 2 {
		return s, nil
	}
	hdr := byteslice.Get(2)
	defer byteslice.Put(hdr)
	_, err := io.ReadFull(conn, hdr)
	if err != nil {
		return nil, err
	}
	if hdr[0] != passwordAuthVersion {
		return nil, ErrBadSocksAuthVersion
	}
	return &readUNameState{ULen: int(hdr[1])}, nil
}

var _readULenState codecState = readULenState{}

type readUNameState struct {
	ULen int
}

func (s *readUNameState) onTraffic(conn gnet.Conn) (codecState, error) {
	if conn.InboundBuffered() < s.ULen {
		return s, nil
	}
	usrBytes := byteslice.Get(s.ULen)
	defer byteslice.Put(usrBytes)
	_, err := io.ReadFull(conn, usrBytes)
	if err != nil {
		return nil, err
	}
	return &readPLenState{Username: string(usrBytes)}, nil
}

var _ codecState = (*readUNameState)(nil)

type readPLenState struct {
	Username string
}

func (s *readPLenState) onTraffic(conn gnet.Conn) (codecState, error) {
	if conn.InboundBuffered() < 1 {
		return s, nil
	}
	hdr := byteslice.Get(1)
	defer byteslice.Put(hdr)
	_, err := io.ReadFull(conn, hdr)
	if err != nil {
		return nil, err
	}
	return &readPasswdState{Username: s.Username, PLen: int(hdr[0])}, nil
}

var _ codecState = (*readPLenState)(nil)

type readPasswdState struct {
	Username string
	PLen     int
}

func (s *readPasswdState) onTraffic(conn gnet.Conn) (codecState, error) {
	if conn.InboundBuffered() < s.PLen {
		return s, nil
	}
	pwdBytes := byteslice.Get(s.PLen)
	defer byteslice.Put(pwdBytes)
	_, err := io.ReadFull(conn, pwdBytes)
	if err != nil {
		return nil, err
	}
	co := conn.Context().(*codec)
	if co.username != s.Username || co.password != string(pwdBytes) {
		conn.Write([]byte{1, 1})
		return nil, ErrAuthFailed
	}
	conn.Write([]byte{1, 0})
	return _authedState, nil
}

var _ codecState = (*readPasswdState)(nil)

type authedState struct {
}

func (s authedState) onTraffic(conn gnet.Conn) (codecState, error) {
	if conn.InboundBuffered() < 4 {
		return s, nil
	}
	hdr := byteslice.Get(4)
	defer byteslice.Put(hdr)
	_, err := io.ReadFull(conn, hdr)
	if err != nil {
		return nil, err
	}
	cmd := hdr[1]
	destAddrType := addrType(hdr[3])
	switch destAddrType {
	case ipv4:
		return &readDstAddr{
			Cmd:   commandType(cmd),
			AType: destAddrType,
			ALen:  4,
		}, nil
	case ipv6:
		return &readDstAddr{
			Cmd:   commandType(cmd),
			AType: destAddrType,
			ALen:  16,
		}, nil
	case domainName:
		return &readDstAddrLen{
			Cmd:   commandType(cmd),
			AType: destAddrType,
		}, nil
	}
	return nil, errors.New("unknown dst address type")
}

var _authedState codecState = authedState{}

type readDstAddrLen struct {
	Cmd   commandType
	AType addrType
}

func (s *readDstAddrLen) onTraffic(conn gnet.Conn) (codecState, error) {
	if conn.InboundBuffered() < 1 {
		return s, nil
	}
	addrLen := byteslice.Get(1)
	defer byteslice.Put(addrLen)
	_, err := io.ReadFull(conn, addrLen)
	if err != nil {
		return nil, err
	}
	return &readDstAddr{
		Cmd:   s.Cmd,
		AType: s.AType,
		ALen:  int(addrLen[0]),
	}, nil
}

var _ codecState = (*readDstAddrLen)(nil)

type readDstAddr struct {
	Cmd   commandType
	AType addrType
	ALen  int
}

func (s *readDstAddr) onTraffic(conn gnet.Conn) (codecState, error) {
	if conn.InboundBuffered() < s.ALen {
		return s, nil
	}
	addrBuf := byteslice.Get(s.ALen)
	defer byteslice.Put(addrBuf)
	_, err := io.ReadFull(conn, addrBuf)
	if err != nil {
		return nil, err
	}
	var dest string
	switch s.AType {
	case ipv4, ipv6:
		dest = net.IP(addrBuf).String()
	case domainName:
		dest = string(addrBuf)
	}
	return &readDstPortState{
		Cmd:  s.Cmd,
		Dest: dest,
	}, nil
}

var _ codecState = (*readDstAddr)(nil)

type readDstPortState struct {
	Cmd  commandType
	Dest string
}

func (s *readDstPortState) onTraffic(conn gnet.Conn) (codecState, error) {
	if conn.InboundBuffered() < 2 {
		return s, nil
	}
	var port uint16
	err := binary.Read(conn, binary.BigEndian, &port)
	if err != nil {
		return nil, err
	}
	return &execCmdState{
		Cmd:  s.Cmd,
		Dest: s.Dest,
		Port: port,
	}, nil
}

var _ codecState = (*readDstPortState)(nil)

type execCmdState struct {
	Cmd  commandType
	Dest string
	Port uint16
}

func (s *execCmdState) onTraffic(conn gnet.Conn) (codecState, error) {
	if s.Cmd != connect {
		res := &response{reply: commandNotSupported}
		buf, _ := res.marshal()
		conn.Write(buf)
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedCommand, s.Cmd)
	}
	co := conn.Context().(*codec)
	srv, err := co.dial(conn, "tcp", net.JoinHostPort(s.Dest, strconv.Itoa(int(s.Port))))
	if err != nil {
		res := &response{reply: generalFailure}
		buf, _ := res.marshal()
		conn.Write(buf)
		return nil, err
	}
	serverAddr, serverPortStr, err := net.SplitHostPort(srv.LocalAddr().String())
	if err != nil {
		srv.Close()
		return nil, err
	}
	serverPort, _ := strconv.Atoi(serverPortStr)

	var bindAddrType addrType
	if ip := net.ParseIP(serverAddr); ip != nil {
		if ip.To4() != nil {
			bindAddrType = ipv4
		} else {
			bindAddrType = ipv6
		}
	} else {
		bindAddrType = domainName
	}
	res := &response{
		reply:        success,
		bindAddrType: bindAddrType,
		bindAddr:     serverAddr,
		bindPort:     uint16(serverPort),
	}
	buf, err := res.marshal()
	if err != nil {
		res = &response{reply: generalFailure}
		buf, _ = res.marshal()
	}
	conn.Write(buf)
	return &connectedState{Srv: srv}, nil
}

var _ codecState = (*execCmdState)(nil)

type connectedState struct {
	Srv gnet.Conn
}

func (s *connectedState) onTraffic(conn gnet.Conn) (codecState, error) {
	n := conn.InboundBuffered()
	if n == 0 {
		return s, nil
	}
	buf := byteslice.Get(n)
	defer byteslice.Put(buf)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	_, err = s.Srv.Write(buf)
	if err != nil {
		return nil, err
	}
	return s, nil
}

var _ codecState = (*connectedState)(nil)

type codec struct {
	state      codecState
	authed     bool
	authMethod byte
	username   string
	password   string
	cli        *gnet.Client
}

func NewGNetServer(addr string, username, password string) *GNetServer {
	cli := lo.Must1(gnet.NewClient(&targetConn{}, gnet.WithMulticore(true)))
	lo.Must0(cli.Start())
	return &GNetServer{
		addr:     addr,
		username: username,
		password: password,
		cli:      cli,
	}
}

func (s *GNetServer) OnOpen(c gnet.Conn) (out []byte, action gnet.Action) {
	c.SetContext(s.newCodec())
	return nil, gnet.None
}

func (s *GNetServer) OnClose(c gnet.Conn, err error) gnet.Action {
	var syscallErr *os.SyscallError
	if !(err == nil || (errors.As(err, &syscallErr) && syscallErr.Err.Error() == "EOF")) {
		logging.Errorf("OnClose connection: %s, err: %v", c.RemoteAddr(), err)
	}
	co := c.Context().(*codec)
	state, ok := co.state.(*connectedState)
	if ok && state.Srv != nil {
		state.Srv.Close()
	}
	return gnet.None
}

func (s *GNetServer) OnTraffic(c gnet.Conn) gnet.Action {
	co := c.Context().(*codec)
	for {
		currentState := co.state
		nextState, err := currentState.onTraffic(c)
		if err != nil {
			logging.Warnf("state OnTraffic failed: %v", err)
			return gnet.Close
		}
		co.state = nextState
		if currentState == nextState {
			break
		}
	}
	return gnet.None
}

func (s *GNetServer) OnBoot(eng gnet.Engine) gnet.Action {
	s.eng = eng
	logging.Infof("gnet server is listening on %s", s.addr)
	return gnet.None
}

func (s *GNetServer) OnShutdown(eng gnet.Engine) {
	logging.Info("gnet server shutdown")
}

func (s *GNetServer) Stop(ctx context.Context) error {
	return s.eng.Stop(ctx)
}

func (s *GNetServer) newCodec() *codec {
	needAuth := s.username != "" || s.password != ""
	authMethod := noAuthRequired
	if needAuth {
		authMethod = passwordAuth
	}
	return &codec{
		state:      _initState,
		authed:     false,
		authMethod: authMethod,
		username:   s.username,
		password:   s.password,
		cli:        s.cli,
	}
}

func (co *codec) dial(clientConn gnet.Conn, network, addr string) (gnet.Conn, error) {
	conn, err := net.DialTimeout(network, addr, time.Second*5)
	if err != nil {
		return nil, err
	}
	return co.cli.EnrollContext(conn, &targetConnCtx{conn: clientConn})
}

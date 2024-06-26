package socks5

import (
	"errors"
	"io"
	"os"

	"github.com/panjf2000/gnet/v2"
	"github.com/panjf2000/gnet/v2/pkg/pool/byteslice"

	"github.com/shanexu/gnet-socks5/internel/logging"
)

type targetConn struct {
	gnet.BuiltinEventEngine
}

func (g targetConn) OnOpen(c gnet.Conn) (out []byte, action gnet.Action) {
	logging.Debugf("open socks5 client, remote: %s", c.RemoteAddr())
	return
}

func (g targetConn) OnClose(c gnet.Conn, err error) (action gnet.Action) {
	logging.Debugf("close socks5 client, remote: %s", c.RemoteAddr())
	var syscallErr *os.SyscallError
	if !(err == nil || (errors.As(err, &syscallErr) && syscallErr.Err.Error() == "EOF")) {
		logging.Errorf("close connection: %s, err: %v", c.RemoteAddr(), err)
	}
	cc := c.Context().(*targetConnCtx)
	cc.conn.Close()
	return
}

func (g targetConn) OnTraffic(c gnet.Conn) (action gnet.Action) {
	cc := c.Context().(*targetConnCtx)
	if c.InboundBuffered() == 0 {
		return gnet.Close
	}
	buf := byteslice.Get(c.InboundBuffered())
	defer byteslice.Put(buf)
	_, err := io.ReadFull(c, buf)
	if err != nil {
		return gnet.Close
	}
	_, err = cc.conn.Write(buf)
	if err != nil {
		return gnet.Close
	}
	return gnet.None
}

type targetConnCtx struct {
	conn gnet.Conn
}

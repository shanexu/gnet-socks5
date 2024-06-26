package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/panjf2000/gnet/v2"
	"github.com/spf13/pflag"

	"github.com/shanexu/gnet-socks5/internel/logging"
	"github.com/shanexu/gnet-socks5/pkg/net/socks5"
)

var (
	bindAddr string
	noAuth   bool
	username string
	password string
)

func init() {
	pflag.StringVarP(&bindAddr, "bind-addr", "b", ":1080", "bind address")
	pflag.BoolVar(&noAuth, "no-auth", false, "disable authentication")
	pflag.StringVar(&username, "username", "username", "username")
	pflag.StringVar(&password, "password", "password", "password")
}

func main() {
	pflag.Parse()

	addr := fmt.Sprintf("tcp://%s", bindAddr)
	if noAuth {
		username = ""
		password = ""
	}
	server := socks5.NewGNetServer(addr, username, password, nil)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		err := gnet.Run(server, addr, gnet.WithMulticore(true), gnet.WithReuseAddr(true))
		if err != nil {
			logging.Fatal(err)
		}
	}()
	<-sigCh
	server.Stop(context.Background())
}

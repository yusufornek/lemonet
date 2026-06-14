// Command lemonet starts the local control panel: it selects a network interface, opens the
// capture handle, serves the web UI on loopback with a per-launch token, and opens the browser.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/pkg/browser"

	"github.com/yusufornek/lemonet/internal/control"
	"github.com/yusufornek/lemonet/internal/engine"
	"github.com/yusufornek/lemonet/internal/server"
	"github.com/yusufornek/lemonet/web"
)

const version = "0.2.0"

func main() {
	iface := flag.String("iface", "", "network interface to use (default: the one facing the gateway)")
	addr := flag.String("addr", "127.0.0.1:0", "loopback address to bind (0 picks a free port)")
	noBrowser := flag.Bool("no-browser", false, "do not open the browser automatically")
	flag.Parse()

	if err := run(*iface, *addr, *noBrowser); err != nil {
		fmt.Fprintln(os.Stderr, "lemonet:", err)
		os.Exit(1)
	}
}

func run(ifaceName, addr string, noBrowser bool) (err error) {
	if err := requirePrivilege(); err != nil {
		return err
	}

	iface, err := pickInterface(ifaceName)
	if err != nil {
		return err
	}

	ctrl, err := control.New(iface)
	if err != nil {
		return err
	}
	defer func() { err = mergeCleanupError(err, ctrl.Close) }()

	token, err := newToken()
	if err != nil {
		return err
	}

	srv := server.New(token, version, ctrl, web.Dist(), iface.Name, iface.IP.String())
	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	ln, err := listenLoopback(addr)
	if err != nil {
		return err
	}

	url := panelURL(ln.Addr().String(), token)
	fmt.Printf("lemonet %s on %s (interface %s)\n", version, iface.Name, iface.Name)
	fmt.Printf("Open: %s\n", url)

	go func() { _ = httpSrv.Serve(ln) }()
	if !noBrowser {
		_ = browser.OpenURL(url)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, shutdownSignals()...)
	<-sig

	fmt.Println("\nlemonet: restoring network and shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	return nil
}

func panelURL(addr, token string) string {
	return fmt.Sprintf("http://%s/#token=%s", addr, token)
}

func mergeCleanupError(err error, cleanup func() error) error {
	return errors.Join(err, cleanup())
}

// pickInterface uses the named interface, or the one whose subnet contains the default gateway.
func pickInterface(name string) (engine.Interface, error) {
	if name != "" {
		return engine.LookupInterface(name)
	}
	gw, err := engine.GatewayIP()
	if err != nil {
		return engine.Interface{}, err
	}
	ifaces, err := engine.ListInterfaces()
	if err != nil {
		return engine.Interface{}, err
	}
	for _, ifi := range ifaces {
		if ifi.Subnet.Contains(gw) {
			return ifi, nil
		}
	}
	if len(ifaces) > 0 {
		return ifaces[0], nil
	}
	return engine.Interface{}, errors.New("no usable network interface found")
}

func requirePrivilege() error {
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		return errors.New("raw packet access requires root; run with sudo")
	}
	return nil
}

func listenLoopback(addr string) (net.Listener, error) {
	if err := validateLoopbackAddr(addr); err != nil {
		return nil, err
	}
	return net.Listen("tcp", addr)
}

func validateLoopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	if host == "" {
		return errors.New("listen address must be loopback; use 127.0.0.1:0, localhost:0, or [::1]:0")
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address %s is not loopback", host)
	}
	return nil
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

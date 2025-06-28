package cmd

import (
	"log"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type buf struct {
	pid uint32
	len uint32
	out [256]byte
}

func Execute() {
	log.Printf("Starting worm \n")
	objs := TracerObjects{}
	if err := LoadTracerObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

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

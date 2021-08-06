package main

/*
#cgo CFLAGS: -I./libbpf-tools
#cgo LDFLAGS: -L./libbpf-tools/.output -lelf -lz -ltcpretrans
#include "libtcpretrans.h"
*/
import "C"

import (
	"fmt"
    "os"
	"time"
)

// race detector will complain, but we only write from a single source, no need
// to block.
var count = 0

func pcount() {
	for ;; {
		fmt.Println("count: ", count)
		time.Sleep(1 * time.Second)
	}
}

// The export statement makes the function available to C
//export gocb
func gocb(arg1 int) {
	// TODO: modify this function to accept an entire event for extra
	// processing.
    fmt.Println("found: ", arg1)
	count++
}

func main() {

	fmt.Println("-------------------------------")
	go pcount()
	os.Exit(int(C.run()))
}

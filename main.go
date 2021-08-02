package main

/*
#cgo CFLAGS: -I./libbpf-tools/.output
#cgo LDFLAGS: -L./libbpf-tools/.output -lelf -lz -ltcpretranslib
#include "tcpretranslib.h"
*/
import "C"

import (
	"fmt"
)

func main() {

	fmt.Println("-------------------------------")

	a := C.run()
    fmt.Println("a: ", a)
}

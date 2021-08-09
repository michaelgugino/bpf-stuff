package main

/*
#cgo CFLAGS: -I./libbpf-tools
#cgo LDFLAGS: -L./libbpf-tools/.output -lelf -lz -ltcpretrans
#include "libtcpretrans.h"
*/
import "C"

import (
	"net/http"
    "os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
        tcpretranscount = promauto.NewCounter(prometheus.CounterOpts{
                Name: "tcpretranscount",
                Help: "The total number of tcpretrans kernel events",
        })
)

// The export statement makes the function available to C
//export gocb
func gocb(arg1 int) {
	// TODO: modify this function to accept an entire event for extra
	// processing.
    tcpretranscount.Inc()
}

func main() {
    http.Handle("/metrics", promhttp.Handler())
    go http.ListenAndServe(":2112", nil)
	os.Exit(int(C.run()))
}

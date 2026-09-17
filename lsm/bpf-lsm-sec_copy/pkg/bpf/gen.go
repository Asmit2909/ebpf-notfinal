package bpf

//go:generate go run -mod=mod github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cflags "-I/usr/include/x86_64-linux-gnu" Bpf lsm_enforce.bpf.c

import _ "embed"

//go:embed vmlinux.h
var VmlinuxH []byte

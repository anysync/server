// +build !windows

package client

import (
	"syscall"
)

func MkFifo(path string) {
	syscall.Mkfifo(path, 0666)
}



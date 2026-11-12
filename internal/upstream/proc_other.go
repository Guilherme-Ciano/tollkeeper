//go:build !unix

package upstream

import "syscall"

func processGroup() *syscall.SysProcAttr {
	return nil
}

func killGroup(int) error {
	return nil
}

//go:build !linux

package processor

import "errors"

func mkfifo(string) error { return errors.New("mkfifo is only exercised on linux") }

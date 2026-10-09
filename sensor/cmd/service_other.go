//go:build !windows

package main

// runAsWindowsService is the non-Windows half of service_windows.go: there is
// no Service Control Manager, so the sensor always runs as a console process
// (which is also how systemd runs it).
func runAsWindowsService(sensorFlags) bool { return false }

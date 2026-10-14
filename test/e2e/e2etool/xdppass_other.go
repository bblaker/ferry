//go:build !linux

package main

import "errors"

func xdpPass([]string) error { return errors.New("xdp-pass needs Linux") }

// Copyright 2010 The win Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows

package win

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	// Library
	libuserenv *windows.LazyDLL

	// Functions
	createEnvironmentBlock  *windows.LazyProc
	destroyEnvironmentBlock *windows.LazyProc
)

func init() {
	// Library
	libuserenv = windows.NewLazySystemDLL("userenv.dll")

	// Functions
	createEnvironmentBlock = libuserenv.NewProc("CreateEnvironmentBlock")
	destroyEnvironmentBlock = libuserenv.NewProc("DestroyEnvironmentBlock")
}

func CreateEnvironmentBlock(lpEnvironment *uintptr, hToken HANDLE, bInherit BOOL) BOOL {
	ret, _, _ := syscall.Syscall(createEnvironmentBlock.Addr(), 3,
		uintptr(unsafe.Pointer(lpEnvironment)),
		uintptr(hToken),
		uintptr(bInherit))
	return BOOL(ret)
}

func DestroyEnvironmentBlock(lpEnvironment uintptr) BOOL {
	ret, _, _ := syscall.Syscall(destroyEnvironmentBlock.Addr(), 1,
		lpEnvironment,
		0,
		0)
	return BOOL(ret)
}

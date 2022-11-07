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

const (
	WTS_CURRENT_SERVER        HANDLE = HANDLE(0)
	WTS_CURRENT_SERVER_HANDLE HANDLE = HANDLE(0)
)

const (
	WTSActive = iota
	WTSConnected
	WTSConnectQuery
	WTSShadow
	WTSDisconnected
	WTSIdle
	WTSListen
	WTSReset
	WTSDown
	WTSInit
)

var (
	// Library
	libwtsapi32 *windows.LazyDLL

	// Functions
	wtsEnumerateSessions *windows.LazyProc
	wtsFreeMemory        *windows.LazyProc
	wtsQueryUserToken    *windows.LazyProc
)

type WTS_SESSION_INFO struct {
	SessionId       uint32
	PWinStationName *uint16
	State           uint32
}

func init() {
	// Library
	libwtsapi32 = windows.NewLazySystemDLL("wtsapi32.dll")

	// Functions
	wtsEnumerateSessions = libwtsapi32.NewProc("WTSEnumerateSessionsW")
	wtsFreeMemory = libwtsapi32.NewProc("WTSFreeMemory")
	wtsQueryUserToken = libwtsapi32.NewProc("WTSQueryUserToken")
}

func WTSEnumerateSessions(hServer HANDLE, Reserved, Version uint32, ppSessionInfo **WTS_SESSION_INFO, pCount *uint32) BOOL {
	ret, _, _ := syscall.Syscall6(wtsEnumerateSessions.Addr(), 5,
		uintptr(hServer),
		uintptr(Reserved),
		uintptr(Version),
		uintptr(unsafe.Pointer(ppSessionInfo)),
		uintptr(unsafe.Pointer(pCount)),
		0)
	return BOOL(ret)
}

func WTSFreeMemory(pMemory uintptr) {
	syscall.Syscall(wtsFreeMemory.Addr(), 1,
		pMemory,
		0,
		0)
}

func WTSQueryUserToken(SessionId uint32, phToken *HANDLE) BOOL {
	ret, _, _ := syscall.Syscall(wtsQueryUserToken.Addr(), 2,
		uintptr(SessionId),
		uintptr(unsafe.Pointer(phToken)),
		0)
	return BOOL(ret)
}

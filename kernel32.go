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

const MAX_PATH = 260
const INVALID_HANDLE_VALUE = 0xffffffff

// Error codes
const (
	ERROR_SUCCESS             = 0
	ERROR_INVALID_FUNCTION    = 1
	ERROR_FILE_NOT_FOUND      = 2
	ERROR_INVALID_PARAMETER   = 87
	ERROR_INSUFFICIENT_BUFFER = 122
	ERROR_MORE_DATA           = 234
)

// GlobalAlloc flags
const (
	GHND          = 0x0042
	GMEM_FIXED    = 0x0000
	GMEM_MOVEABLE = 0x0002
	GMEM_ZEROINIT = 0x0040
	GPTR          = GMEM_FIXED | GMEM_ZEROINIT
)

// Predefined locale ids
const (
	LOCALE_CUSTOM_DEFAULT     LCID = 0x0c00
	LOCALE_CUSTOM_UI_DEFAULT  LCID = 0x1400
	LOCALE_CUSTOM_UNSPECIFIED LCID = 0x1000
	LOCALE_INVARIANT          LCID = 0x007f
	LOCALE_USER_DEFAULT       LCID = 0x0400
	LOCALE_SYSTEM_DEFAULT     LCID = 0x0800
)

// LCTYPE constants
const (
	LOCALE_SDECIMAL          LCTYPE = 14
	LOCALE_STHOUSAND         LCTYPE = 15
	LOCALE_SISO3166CTRYNAME  LCTYPE = 0x5a
	LOCALE_SISO3166CTRYNAME2 LCTYPE = 0x68
	LOCALE_SISO639LANGNAME   LCTYPE = 0x59
	LOCALE_SISO639LANGNAME2  LCTYPE = 0x67
)

// dwDesiredAccess
const (
	GENERIC_READ    = 0x80000000
	GENERIC_WRITE   = 0x40000000
	GENERIC_EXECUTE = 0x20000000
	GENERIC_ALL     = 0x10000000
)

// dwShareMode
const (
	FILE_SHARE_READ   = 0x00000001
	FILE_SHARE_WRITE  = 0x00000002
	FILE_SHARE_DELETE = 0x00000004
)

// dwCreationDisposition
const (
	CREATE_NEW        = 1
	CREATE_ALWAYS     = 2
	OPEN_EXISTING     = 3
	OPEN_ALWAYS       = 4
	TRUNCATE_EXISTING = 5
)

// dwFlagsAndAttributes
const (
	FILE_FLAG_WRITE_THROUGH   = 0x80000000
	FILE_FLAG_NO_BUFFERING    = 0x20000000
	FILE_FLAG_RANDOM_ACCESS   = 0x10000000
	FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
	FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
	FILE_FLAG_OVERLAPPED      = 0x40000000
)

// // dwFlagsAndAttributes
const (
	FILE_ATTRIBUTE_READONLY  = 0x00000001
	FILE_ATTRIBUTE_HIDDEN    = 0x00000002
	FILE_ATTRIBUTE_SYSTEM    = 0x00000004
	FILE_ATTRIBUTE_DIRECTORY = 0x00000010
	FILE_ATTRIBUTE_ARCHIVE   = 0x00000020
	FILE_ATTRIBUTE_DEVICE    = 0x00000040
	FILE_ATTRIBUTE_NORMAL    = 0x00000080
	FILE_ATTRIBUTE_TEMPORARY = 0x00000100
)

const (
	STD_INPUT_HANDLE  = 0xfffffff6
	STD_OUTPUT_HANDLE = 0xfffffff5
	STD_ERROR_HANDLE  = 0xfffffff4
)

const (
	HF32_DEFAULT        = 1
	HF32_SHARED         = 2
	LF32_FIXED          = 0x1
	LF32_FREE           = 0x2
	LF32_MOVEABLE       = 0x4
	MAX_MODULE_NAME32   = 255
	TH32CS_SNAPHEAPLIST = 0x1
	TH32CS_SNAPPROCESS  = 0x2
	TH32CS_SNAPTHREAD   = 0x4
	TH32CS_SNAPMODULE   = 0x8
	TH32CS_SNAPALL      = TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE
	TH32CS_INHERIT      = 0x80000000
)

const (
	WAIT_OBJECT_0 = 0
	INFINITE      = 0xFFFFFFFF
)

const (
	PIPE_ACCESS_INBOUND  = 0x00000001
	PIPE_ACCESS_OUTBOUND = 0x00000002
	PIPE_ACCESS_DUPLEX   = 0x00000003

	PIPE_CLIENT_END = 0x00000000
	PIPE_SERVER_END = 0x00000001

	PIPE_WAIT                  = 0x00000000
	PIPE_NOWAIT                = 0x00000001
	PIPE_READMODE_BYTE         = 0x00000000
	PIPE_READMODE_MESSAGE      = 0x00000002
	PIPE_TYPE_BYTE             = 0x00000000
	PIPE_TYPE_MESSAGE          = 0x00000004
	PIPE_ACCEPT_REMOTE_CLIENTS = 0x00000000
	PIPE_REJECT_REMOTE_CLIENTS = 0x00000008

	PIPE_UNLIMITED_INSTANCES = 255
)

const (
	DEBUG_PROCESS           = 0x00000001
	DEBUG_ONLY_THIS_PROCESS = 0x00000002
	CREATE_SUSPENDED        = 0x00000004
	DETACHED_PROCESS        = 0x00000008

	CREATE_NEW_CONSOLE    = 0x00000010
	NORMAL_PRIORITY_CLASS = 0x00000020
	IDLE_PRIORITY_CLASS   = 0x00000040
	HIGH_PRIORITY_CLASS   = 0x00000080

	REALTIME_PRIORITY_CLASS    = 0x00000100
	CREATE_NEW_PROCESS_GROUP   = 0x00000200
	CREATE_UNICODE_ENVIRONMENT = 0x00000400
	CREATE_SEPARATE_WOW_VDM    = 0x00000800

	CREATE_SHARED_WOW_VDM       = 0x00001000
	CREATE_FORCEDOS             = 0x00002000
	BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
	ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000

	INHERIT_PARENT_AFFINITY      = 0x00010000
	INHERIT_CALLER_PRIORITY      = 0x00020000
	CREATE_PROTECTED_PROCESS     = 0x00040000
	EXTENDED_STARTUPINFO_PRESENT = 0x00080000

	PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000
	PROCESS_MODE_BACKGROUND_END   = 0x00200000

	CREATE_BREAKAWAY_FROM_JOB        = 0x01000000
	CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000
	CREATE_DEFAULT_ERROR_MODE        = 0x04000000
	CREATE_NO_WINDOW                 = 0x08000000

	PROFILE_USER                 = 0x10000000
	PROFILE_KERNEL               = 0x20000000
	PROFILE_SERVER               = 0x40000000
	CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000

	STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000

	THREAD_BASE_PRIORITY_LOWRT = 15
	THREAD_BASE_PRIORITY_MAX   = 2
	THREAD_BASE_PRIORITY_MIN   = -2
	THREAD_BASE_PRIORITY_IDLE  = -15

	THREAD_PRIORITY_LOWEST       = THREAD_BASE_PRIORITY_MIN
	THREAD_PRIORITY_BELOW_NORMAL = THREAD_PRIORITY_LOWEST + 1
	THREAD_PRIORITY_NORMAL       = 0
	THREAD_PRIORITY_HIGHEST      = THREAD_BASE_PRIORITY_MAX
	THREAD_PRIORITY_ABOVE_NORMAL = THREAD_PRIORITY_HIGHEST - 1

	THREAD_PRIORITY_TIME_CRITICAL = THREAD_BASE_PRIORITY_LOWRT
	THREAD_PRIORITY_IDLE          = THREAD_BASE_PRIORITY_IDLE

	THREAD_MODE_BACKGROUND_BEGIN = 0x00010000
	THREAD_MODE_BACKGROUND_END   = 0x00020000
)

var (
	// Library
	libkernel32 *windows.LazyDLL

	// Functions
	activateActCtx                     *windows.LazyProc
	closeHandle                        *windows.LazyProc
	createActCtx                       *windows.LazyProc
	fileTimeToSystemTime               *windows.LazyProc
	findResource                       *windows.LazyProc
	getConsoleTitle                    *windows.LazyProc
	getConsoleWindow                   *windows.LazyProc
	getCurrentProcessId                *windows.LazyProc
	getCurrentThreadId                 *windows.LazyProc
	getLastError                       *windows.LazyProc
	getLocaleInfo                      *windows.LazyProc
	getLogicalDriveStrings             *windows.LazyProc
	getModuleHandle                    *windows.LazyProc
	getNumberFormat                    *windows.LazyProc
	getPhysicallyInstalledSystemMemory *windows.LazyProc
	getProfileString                   *windows.LazyProc
	getThreadLocale                    *windows.LazyProc
	getThreadUILanguage                *windows.LazyProc
	getVersion                         *windows.LazyProc
	globalAlloc                        *windows.LazyProc
	globalFree                         *windows.LazyProc
	globalLock                         *windows.LazyProc
	globalUnlock                       *windows.LazyProc
	moveMemory                         *windows.LazyProc
	mulDiv                             *windows.LazyProc
	loadResource                       *windows.LazyProc
	lockResource                       *windows.LazyProc
	openProcess                        *windows.LazyProc
	setLastError                       *windows.LazyProc
	sizeofResource                     *windows.LazyProc
	systemTimeToFileTime               *windows.LazyProc
	writeProcessMemory                 *windows.LazyProc
	createMutex                        *windows.LazyProc
	releaseMutex                       *windows.LazyProc
	expandEnvironmentStrings           *windows.LazyProc
	createFile                         *windows.LazyProc
	writeFile                          *windows.LazyProc
	readFile                           *windows.LazyProc
	createToolhelp32Snapshot           *windows.LazyProc
	module32First                      *windows.LazyProc
	module32Next                       *windows.LazyProc
	waitForSingleObject                *windows.LazyProc
	waitForMultipleObjects             *windows.LazyProc
	createEvent                        *windows.LazyProc
	setEvent                           *windows.LazyProc
	resetEvent                         *windows.LazyProc
	createProcess                      *windows.LazyProc
)

type (
	ATOM          uint16
	HANDLE        uintptr
	HGLOBAL       HANDLE
	HINSTANCE     HANDLE
	LCID          uint32
	LCTYPE        uint32
	LANGID        uint16
	HMODULE       uintptr
	HWINEVENTHOOK HANDLE
	HRSRC         uintptr
)

type FILETIME struct {
	DwLowDateTime  uint32
	DwHighDateTime uint32
}

type NUMBERFMT struct {
	NumDigits     uint32
	LeadingZero   uint32
	Grouping      uint32
	LpDecimalSep  *uint16
	LpThousandSep *uint16
	NegativeOrder uint32
}

type SYSTEMTIME struct {
	WYear         uint16
	WMonth        uint16
	WDayOfWeek    uint16
	WDay          uint16
	WHour         uint16
	WMinute       uint16
	WSecond       uint16
	WMilliseconds uint16
}

type ACTCTX struct {
	size                  uint32
	Flags                 uint32
	Source                *uint16 // UTF-16 string
	ProcessorArchitecture uint16
	LangID                uint16
	AssemblyDirectory     *uint16 // UTF-16 string
	ResourceName          *uint16 // UTF-16 string
	ApplicationName       *uint16 // UTF-16 string
	Module                HMODULE
}

type SECURITY_ATTRIBUTES struct {
	NLength              uint32
	LPSecurityDescriptor uintptr
	BInheritHandle       BOOL
}

type OVERLAPPED_OFFSET struct {
	Offset     uint32
	OffsetHigh uint32
}

type OVERLAPPED struct {
	Internal     uint32
	InternalHigh uint32
	Overlapped   OVERLAPPED_OFFSET
	HEvent       HANDLE
}

type MODULEENTRY32 struct {
	DwSize        uint32
	Th32ModuleID  uint32
	Th32ProcessID uint32
	GlblcntUsage  uint32
	ProccntUsage  uint32
	ModBaseAddr   *byte
	ModBaseSize   uint32
	HModule       HMODULE
	SzModule      [MAX_MODULE_NAME32 + 1]byte
	SzExePath     [MAX_PATH]byte
}

type PROCESS_INFORMATION struct {
	HProcess    HANDLE
	HThread     HANDLE
	DwProcessId uint32
	DwThreadId  uint32
}

func init() {
	// Library
	libkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	// Functions
	activateActCtx = libkernel32.NewProc("ActivateActCtx")
	closeHandle = libkernel32.NewProc("CloseHandle")
	createActCtx = libkernel32.NewProc("CreateActCtxW")
	fileTimeToSystemTime = libkernel32.NewProc("FileTimeToSystemTime")
	findResource = libkernel32.NewProc("FindResourceW")
	getConsoleTitle = libkernel32.NewProc("GetConsoleTitleW")
	getConsoleWindow = libkernel32.NewProc("GetConsoleWindow")
	getCurrentProcessId = libkernel32.NewProc("GetCurrentProcessId")
	getCurrentThreadId = libkernel32.NewProc("GetCurrentThreadId")
	getLastError = libkernel32.NewProc("GetLastError")
	getLocaleInfo = libkernel32.NewProc("GetLocaleInfoW")
	getLogicalDriveStrings = libkernel32.NewProc("GetLogicalDriveStringsW")
	getModuleHandle = libkernel32.NewProc("GetModuleHandleW")
	getNumberFormat = libkernel32.NewProc("GetNumberFormatW")
	getPhysicallyInstalledSystemMemory = libkernel32.NewProc("GetPhysicallyInstalledSystemMemory")
	getProfileString = libkernel32.NewProc("GetProfileStringW")
	getThreadLocale = libkernel32.NewProc("GetThreadLocale")
	getThreadUILanguage = libkernel32.NewProc("GetThreadUILanguage")
	getVersion = libkernel32.NewProc("GetVersion")
	globalAlloc = libkernel32.NewProc("GlobalAlloc")
	globalFree = libkernel32.NewProc("GlobalFree")
	globalLock = libkernel32.NewProc("GlobalLock")
	globalUnlock = libkernel32.NewProc("GlobalUnlock")
	moveMemory = libkernel32.NewProc("RtlMoveMemory")
	mulDiv = libkernel32.NewProc("MulDiv")
	loadResource = libkernel32.NewProc("LoadResource")
	lockResource = libkernel32.NewProc("LockResource")
	openProcess = libkernel32.NewProc("OpenProcess")
	setLastError = libkernel32.NewProc("SetLastError")
	sizeofResource = libkernel32.NewProc("SizeofResource")
	systemTimeToFileTime = libkernel32.NewProc("SystemTimeToFileTime")
	writeProcessMemory = libkernel32.NewProc("WriteProcessMemory")
	createMutex = libkernel32.NewProc("CreateMutexW")
	releaseMutex = libkernel32.NewProc("ReleaseMutex")
	expandEnvironmentStrings = libkernel32.NewProc("ExpandEnvironmentStringsW")
	createFile = libkernel32.NewProc("CreateFileW")
	writeFile = libkernel32.NewProc("WriteFile")
	readFile = libkernel32.NewProc("ReadFile")
	createToolhelp32Snapshot = libkernel32.NewProc("CreateToolhelp32Snapshot")
	module32First = libkernel32.NewProc("Module32First")
	module32Next = libkernel32.NewProc("Module32Next")
	waitForSingleObject = libkernel32.NewProc("WaitForSingleObject")
	waitForMultipleObjects = libkernel32.NewProc("WaitForMultipleObjects")
	createEvent = libkernel32.NewProc("CreateEventW")
	setEvent = libkernel32.NewProc("SetEvent")
	resetEvent = libkernel32.NewProc("ResetEvent")
	createProcess = libkernel32.NewProc("CreateProcessW")
}

func ActivateActCtx(ctx HANDLE) (uintptr, bool) {
	var cookie uintptr
	ret, _, _ := syscall.Syscall(activateActCtx.Addr(), 2,
		uintptr(ctx),
		uintptr(unsafe.Pointer(&cookie)),
		0)
	return cookie, ret != 0
}

func CloseHandle(hObject HANDLE) bool {
	ret, _, _ := syscall.Syscall(closeHandle.Addr(), 1,
		uintptr(hObject),
		0,
		0)

	return ret != 0
}

func CreateActCtx(ctx *ACTCTX) HANDLE {
	if ctx != nil {
		ctx.size = uint32(unsafe.Sizeof(*ctx))
	}
	ret, _, _ := syscall.Syscall(
		createActCtx.Addr(),
		1,
		uintptr(unsafe.Pointer(ctx)),
		0,
		0)
	return HANDLE(ret)
}

func FileTimeToSystemTime(lpFileTime *FILETIME, lpSystemTime *SYSTEMTIME) bool {
	ret, _, _ := syscall.Syscall(fileTimeToSystemTime.Addr(), 2,
		uintptr(unsafe.Pointer(lpFileTime)),
		uintptr(unsafe.Pointer(lpSystemTime)),
		0)

	return ret != 0
}

func FindResource(hModule HMODULE, lpName, lpType *uint16) HRSRC {
	ret, _, _ := syscall.Syscall(findResource.Addr(), 3,
		uintptr(hModule),
		uintptr(unsafe.Pointer(lpName)),
		uintptr(unsafe.Pointer(lpType)))

	return HRSRC(ret)
}

func GetConsoleTitle(lpConsoleTitle *uint16, nSize uint32) uint32 {
	ret, _, _ := syscall.Syscall(getConsoleTitle.Addr(), 2,
		uintptr(unsafe.Pointer(lpConsoleTitle)),
		uintptr(nSize),
		0)

	return uint32(ret)
}

func GetConsoleWindow() HWND {
	ret, _, _ := syscall.Syscall(getConsoleWindow.Addr(), 0,
		0,
		0,
		0)

	return HWND(ret)
}

func GetCurrentProcessId() uint32 {
	ret, _, _ := syscall.Syscall(getCurrentProcessId.Addr(), 0,
		0,
		0,
		0)

	return uint32(ret)
}

func GetCurrentThreadId() uint32 {
	ret, _, _ := syscall.Syscall(getCurrentThreadId.Addr(), 0,
		0,
		0,
		0)

	return uint32(ret)
}

func GetLastError() uint32 {
	ret, _, _ := syscall.Syscall(getLastError.Addr(), 0,
		0,
		0,
		0)

	return uint32(ret)
}

func GetLocaleInfo(Locale LCID, LCType LCTYPE, lpLCData *uint16, cchData int32) int32 {
	ret, _, _ := syscall.Syscall6(getLocaleInfo.Addr(), 4,
		uintptr(Locale),
		uintptr(LCType),
		uintptr(unsafe.Pointer(lpLCData)),
		uintptr(cchData),
		0,
		0)

	return int32(ret)
}

func GetLogicalDriveStrings(nBufferLength uint32, lpBuffer *uint16) uint32 {
	ret, _, _ := syscall.Syscall(getLogicalDriveStrings.Addr(), 2,
		uintptr(nBufferLength),
		uintptr(unsafe.Pointer(lpBuffer)),
		0)

	return uint32(ret)
}

func GetModuleHandle(lpModuleName *uint16) HINSTANCE {
	ret, _, _ := syscall.Syscall(getModuleHandle.Addr(), 1,
		uintptr(unsafe.Pointer(lpModuleName)),
		0,
		0)

	return HINSTANCE(ret)
}

func GetNumberFormat(Locale LCID, dwFlags uint32, lpValue *uint16, lpFormat *NUMBERFMT, lpNumberStr *uint16, cchNumber int32) int32 {
	ret, _, _ := syscall.Syscall6(getNumberFormat.Addr(), 6,
		uintptr(Locale),
		uintptr(dwFlags),
		uintptr(unsafe.Pointer(lpValue)),
		uintptr(unsafe.Pointer(lpFormat)),
		uintptr(unsafe.Pointer(lpNumberStr)),
		uintptr(cchNumber))

	return int32(ret)
}

func GetPhysicallyInstalledSystemMemory(totalMemoryInKilobytes *uint64) bool {
	if getPhysicallyInstalledSystemMemory.Find() != nil {
		return false
	}
	ret, _, _ := syscall.Syscall(getPhysicallyInstalledSystemMemory.Addr(), 1,
		uintptr(unsafe.Pointer(totalMemoryInKilobytes)),
		0,
		0)

	return ret != 0
}

func GetProfileString(lpAppName, lpKeyName, lpDefault *uint16, lpReturnedString uintptr, nSize uint32) bool {
	ret, _, _ := syscall.Syscall6(getProfileString.Addr(), 5,
		uintptr(unsafe.Pointer(lpAppName)),
		uintptr(unsafe.Pointer(lpKeyName)),
		uintptr(unsafe.Pointer(lpDefault)),
		lpReturnedString,
		uintptr(nSize),
		0)
	return ret != 0
}

func GetThreadLocale() LCID {
	ret, _, _ := syscall.Syscall(getThreadLocale.Addr(), 0,
		0,
		0,
		0)

	return LCID(ret)
}

func GetThreadUILanguage() LANGID {
	if getThreadUILanguage.Find() != nil {
		return 0
	}

	ret, _, _ := syscall.Syscall(getThreadUILanguage.Addr(), 0,
		0,
		0,
		0)

	return LANGID(ret)
}

func GetVersion() uint32 {
	ret, _, _ := syscall.Syscall(getVersion.Addr(), 0,
		0,
		0,
		0)
	return uint32(ret)
}

func GlobalAlloc(uFlags uint32, dwBytes uintptr) HGLOBAL {
	ret, _, _ := syscall.Syscall(globalAlloc.Addr(), 2,
		uintptr(uFlags),
		dwBytes,
		0)

	return HGLOBAL(ret)
}

func GlobalFree(hMem HGLOBAL) HGLOBAL {
	ret, _, _ := syscall.Syscall(globalFree.Addr(), 1,
		uintptr(hMem),
		0,
		0)

	return HGLOBAL(ret)
}

func GlobalLock(hMem HGLOBAL) unsafe.Pointer {
	ret, _, _ := syscall.Syscall(globalLock.Addr(), 1,
		uintptr(hMem),
		0,
		0)

	return unsafe.Pointer(ret)
}

func GlobalUnlock(hMem HGLOBAL) bool {
	ret, _, _ := syscall.Syscall(globalUnlock.Addr(), 1,
		uintptr(hMem),
		0,
		0)

	return ret != 0
}

func MoveMemory(destination, source unsafe.Pointer, length uintptr) {
	syscall.Syscall(moveMemory.Addr(), 3,
		uintptr(unsafe.Pointer(destination)),
		uintptr(source),
		uintptr(length))
}

func MulDiv(nNumber, nNumerator, nDenominator int32) int32 {
	ret, _, _ := syscall.Syscall(mulDiv.Addr(), 3,
		uintptr(nNumber),
		uintptr(nNumerator),
		uintptr(nDenominator))

	return int32(ret)
}

func LoadResource(hModule HMODULE, hResInfo HRSRC) HGLOBAL {
	ret, _, _ := syscall.Syscall(loadResource.Addr(), 2,
		uintptr(hModule),
		uintptr(hResInfo),
		0)

	return HGLOBAL(ret)
}

func LockResource(hResData HGLOBAL) uintptr {
	ret, _, _ := syscall.Syscall(lockResource.Addr(), 1,
		uintptr(hResData),
		0,
		0)

	return ret
}

func SetLastError(dwErrorCode uint32) {
	syscall.Syscall(setLastError.Addr(), 1,
		uintptr(dwErrorCode),
		0,
		0)
}

func SizeofResource(hModule HMODULE, hResInfo HRSRC) uint32 {
	ret, _, _ := syscall.Syscall(sizeofResource.Addr(), 2,
		uintptr(hModule),
		uintptr(hResInfo),
		0)

	return uint32(ret)
}

func SystemTimeToFileTime(lpSystemTime *SYSTEMTIME, lpFileTime *FILETIME) bool {
	ret, _, _ := syscall.Syscall(systemTimeToFileTime.Addr(), 2,
		uintptr(unsafe.Pointer(lpSystemTime)),
		uintptr(unsafe.Pointer(lpFileTime)),
		0)

	return ret != 0
}

func WriteProcessMemory(hProcess HANDLE, lpBaseAddress, lpBuffer uintptr, nSize uintptr, lpNumberOfBytesWritten uintptr) bool {
	ret, _, _ := syscall.Syscall6(writeProcessMemory.Addr(), 5,
		uintptr(hProcess),
		lpBaseAddress,
		lpBuffer,
		nSize,
		lpNumberOfBytesWritten,
		0)

	return ret != 0
}

func OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId uintptr) HANDLE {
	ret, _, _ := syscall.Syscall(openProcess.Addr(), 3,
		dwDesiredAccess,
		bInheritHandle,
		dwProcessId)

	return HANDLE(ret)
}

func CreateMutex(attr uintptr, bInitialOwner BOOL, lpName string) (HANDLE, syscall.Errno) {
	name, _ := syscall.UTF16PtrFromString(lpName)
	h, _, err := syscall.Syscall(createMutex.Addr(), 3, attr, uintptr(bInitialOwner), uintptr(unsafe.Pointer(name)))
	return HANDLE(h), err
}
func ReleaseMutex(handle HANDLE) bool {
	b, _, _ := syscall.Syscall(releaseMutex.Addr(), 1, uintptr(handle), 0, 0)
	return b == TRUE
}

func ExpandEnvironmentStrings(LPCWSTR string, LPWSTR *uint16, nSize uint32) uint32 {
	src, _ := syscall.UTF16PtrFromString(LPCWSTR)

	ret, _, _ := syscall.Syscall(expandEnvironmentStrings.Addr(), 3,
		uintptr(unsafe.Pointer(src)),
		uintptr(unsafe.Pointer(LPWSTR)),
		uintptr(nSize))

	return uint32(ret)
}

func CreateFile(lpFileName string, dwDesiredAccess, dwShareMode uint32, lpSecurityAttributes *SECURITY_ATTRIBUTES,
	dwCreationDisposition, dwFlagsAndAttributes uint32, hTemplateFile HANDLE) HANDLE {
	fileName, _ := syscall.UTF16PtrFromString(lpFileName)

	ret, _, _ := syscall.Syscall9(createFile.Addr(), 7,
		uintptr(unsafe.Pointer(fileName)),
		uintptr(dwDesiredAccess),
		uintptr(dwShareMode),
		uintptr(unsafe.Pointer(lpSecurityAttributes)),
		uintptr(dwCreationDisposition),
		uintptr(dwFlagsAndAttributes),
		uintptr(hTemplateFile),
		0,
		0)

	return HANDLE(ret)
}

func WriteFile(hFile HANDLE, lpBuffer uintptr, nNumberOfBytesToWrite uint32, lpNumberOfBytesWritten *uint32, lpOverlapped *OVERLAPPED) BOOL {
	ret, _, _ := syscall.Syscall6(writeFile.Addr(), 5,
		uintptr(hFile),
		uintptr(lpBuffer),
		uintptr(nNumberOfBytesToWrite),
		uintptr(unsafe.Pointer(lpNumberOfBytesWritten)),
		uintptr(unsafe.Pointer(lpOverlapped)),
		0)

	return BOOL(ret)
}

func ReadFile(hFile HANDLE, lpBuffer uintptr, nNumberOfBytesToRead uint32, lpNumberOfBytesRead *uint32, lpOverlapped *OVERLAPPED) BOOL {
	ret, _, _ := syscall.Syscall6(readFile.Addr(), 5,
		uintptr(hFile),
		uintptr(lpBuffer),
		uintptr(nNumberOfBytesToRead),
		uintptr(unsafe.Pointer(lpNumberOfBytesRead)),
		uintptr(unsafe.Pointer(lpOverlapped)),
		0)

	return BOOL(ret)
}

func CreateToolhelp32Snapshot(dwFlags, th32ProcessID uint32) HANDLE {
	ret, _, _ := syscall.Syscall(createToolhelp32Snapshot.Addr(), 2,
		uintptr(dwFlags),
		uintptr(th32ProcessID),
		0)

	return HANDLE(ret)
}

func Module32First(hSnapshot HANDLE, lpme *MODULEENTRY32) HANDLE {
	ret, _, _ := syscall.Syscall(module32First.Addr(), 2,
		uintptr(hSnapshot),
		uintptr(unsafe.Pointer(lpme)),
		0)

	return HANDLE(ret)
}

func Module32Next(hSnapshot HANDLE, lpme *MODULEENTRY32) HANDLE {
	ret, _, _ := syscall.Syscall(module32Next.Addr(), 2,
		uintptr(hSnapshot),
		uintptr(unsafe.Pointer(lpme)),
		0)

	return HANDLE(ret)
}

func WaitForSingleObject(hHandle HANDLE, dwMilliseconds uint32) uint32 {
	ret, _, _ := syscall.Syscall(waitForSingleObject.Addr(), 2,
		uintptr(hHandle),
		uintptr(dwMilliseconds),
		0)

	return uint32(ret)
}

func WaitForMultipleObjects(nCount uint32, lpHandles *HANDLE, bWaitAll BOOL, dwMilliseconds uint32) uint32 {
	ret, _, _ := syscall.Syscall6(waitForMultipleObjects.Addr(), 4,
		uintptr(nCount),
		uintptr(unsafe.Pointer(lpHandles)),
		uintptr(bWaitAll),
		uintptr(dwMilliseconds),
		0,
		0)

	return uint32(ret)
}

func CreateEvent(lpEventAttributes *SECURITY_ATTRIBUTES, bManualReset BOOL, bInitialState BOOL, lpName *string) HANDLE {
	name := UTF16PtrFromString(lpName)

	ret, _, _ := syscall.Syscall6(createEvent.Addr(), 4,
		uintptr(unsafe.Pointer(lpEventAttributes)),
		uintptr(bManualReset),
		uintptr(bInitialState),
		uintptr(unsafe.Pointer(name)),
		0,
		0)

	return HANDLE(ret)
}

func SetEvent(hEvent HANDLE) BOOL {
	ret, _, _ := syscall.Syscall(setEvent.Addr(), 1,
		uintptr(hEvent),
		0,
		0)

	return BOOL(ret)
}

func ResetEvent(hEvent HANDLE) BOOL {
	ret, _, _ := syscall.Syscall(resetEvent.Addr(), 1,
		uintptr(hEvent),
		0,
		0)

	return BOOL(ret)
}

func CreateProcess(lpApplicationName, lpCommandLine *string, lpProcessAttributes, lpThreadAttributes *SECURITY_ATTRIBUTES,
	bInheritHandles BOOL, dwCreationFlags uint32, lpEnvironment uintptr, lpCurrentDirectory *string, lpStartupInfo *STARTUPINFO, lpProcessInformation *PROCESS_INFORMATION) BOOL {
	applicationName := UTF16PtrFromString(lpApplicationName)
	commandLine := UTF16PtrFromString(lpCommandLine)
	currentDirectory := UTF16PtrFromString(lpCurrentDirectory)

	ret, _, _ := syscall.Syscall12(createProcess.Addr(), 10,
		uintptr(unsafe.Pointer(applicationName)),
		uintptr(unsafe.Pointer(commandLine)),
		uintptr(unsafe.Pointer(lpProcessAttributes)),
		uintptr(unsafe.Pointer(lpThreadAttributes)),
		uintptr(bInheritHandles),
		uintptr(dwCreationFlags),
		lpEnvironment,
		uintptr(unsafe.Pointer(currentDirectory)),
		uintptr(unsafe.Pointer(lpStartupInfo)),
		uintptr(unsafe.Pointer(lpProcessInformation)),
		0,
		0)
	return BOOL(ret)
}

//go:build windows

package wfp

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// The filtering platform's calls, wrapped so that the error they report is the error that
// happened.
//
// Written rather than borrowed, and that is not tidiness. The generated wrappers in the
// package this borrows its types from do:
//
//	r1, _, e1 := syscall.Syscall(...)
//	if r1 != 0 { err = errnoErr(e1) }
//
// These functions return their error code *in the return value*; e1 is whatever
// GetLastError happened to be holding, which is unrelated. So failure is detected correctly
// and described wrongly. That is survivable for a caller that only asks whether it worked,
// which is what that package does — and not for this one, which has to tell FWP_E_ALREADY_
// EXISTS from a refusal, because the provider and sublayer outlive the process and every
// reconcile after the first finds them there.
//
// It also means the deletes exist here. That package has none: a dynamic session removes
// everything when the process ends, so it never needed one (ADR-0030).
var (
	modfwpuclnt = windows.NewLazySystemDLL("fwpuclnt.dll")

	procFwpmEngineOpen0          = modfwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0         = modfwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmProviderAdd0         = modfwpuclnt.NewProc("FwpmProviderAdd0")
	procFwpmProviderDeleteByKey0 = modfwpuclnt.NewProc("FwpmProviderDeleteByKey0")
	procFwpmSubLayerAdd0         = modfwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmSubLayerDeleteByKey0 = modfwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmFilterAdd0           = modfwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteByKey0   = modfwpuclnt.NewProc("FwpmFilterDeleteByKey0")
	procFwpmTransactionBegin0    = modfwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0   = modfwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0    = modfwpuclnt.NewProc("FwpmTransactionAbort0")
	procFwpmFreeMemory0          = modfwpuclnt.NewProc("FwpmFreeMemory0")
)

// result turns a filtering-platform return value into an error.
//
// Zero is success. Anything else is the code itself, which is what makes FWP_E_ALREADY_EXISTS
// distinguishable from everything else that can go wrong.
func result(r uintptr) error {
	if r == 0 {
		return nil
	}
	return windows.Errno(r)
}

func fwpmEngineOpen0(serverName *uint16, authnService wtRpcCAuthN, authIdentity *uintptr, session *wtFwpmSession0, engineHandle unsafe.Pointer) error {
	r, _, _ := procFwpmEngineOpen0.Call(uintptr(unsafe.Pointer(serverName)), uintptr(authnService),
		uintptr(unsafe.Pointer(authIdentity)), uintptr(unsafe.Pointer(session)), uintptr(engineHandle))
	return result(r)
}

func fwpmEngineClose0(engine uintptr) error {
	r, _, _ := procFwpmEngineClose0.Call(engine)
	return result(r)
}

func fwpmProviderAdd0(engine uintptr, provider *wtFwpmProvider0, sd uintptr) error {
	r, _, _ := procFwpmProviderAdd0.Call(engine, uintptr(unsafe.Pointer(provider)), sd)
	return result(r)
}

func fwpmProviderDeleteByKey0(engine uintptr, key *windows.GUID) error {
	r, _, _ := procFwpmProviderDeleteByKey0.Call(engine, uintptr(unsafe.Pointer(key)))
	return result(r)
}

func fwpmSubLayerAdd0(engine uintptr, sublayer *wtFwpmSublayer0, sd uintptr) error {
	r, _, _ := procFwpmSubLayerAdd0.Call(engine, uintptr(unsafe.Pointer(sublayer)), sd)
	return result(r)
}

func fwpmSubLayerDeleteByKey0(engine uintptr, key *windows.GUID) error {
	r, _, _ := procFwpmSubLayerDeleteByKey0.Call(engine, uintptr(unsafe.Pointer(key)))
	return result(r)
}

func fwpmFilterAdd0(engine uintptr, filter *wtFwpmFilter0, sd uintptr, id *uint64) error {
	r, _, _ := procFwpmFilterAdd0.Call(engine, uintptr(unsafe.Pointer(filter)), sd, uintptr(unsafe.Pointer(id)))
	return result(r)
}

// fwpmFilterDeleteByKey0 removes one filter by the key it was created with.
//
// By key rather than by the id the engine assigns, and that is what makes removal possible for
// a process that did not create them. An id is handed back at creation and known only to
// whoever was there; a key is a name meshp chooses, so a daemon that has just started can name
// yesterday's filters without having kept a list of numbers.
func fwpmFilterDeleteByKey0(engine uintptr, key *windows.GUID) error {
	r, _, _ := procFwpmFilterDeleteByKey0.Call(engine, uintptr(unsafe.Pointer(key)))
	return result(r)
}

func fwpmTransactionBegin0(engine uintptr, flags uint32) error {
	r, _, _ := procFwpmTransactionBegin0.Call(engine, uintptr(flags))
	return result(r)
}

func fwpmTransactionCommit0(engine uintptr) error {
	r, _, _ := procFwpmTransactionCommit0.Call(engine)
	return result(r)
}

func fwpmTransactionAbort0(engine uintptr) error {
	r, _, _ := procFwpmTransactionAbort0.Call(engine)
	return result(r)
}

func fwpmFreeMemory0(p unsafe.Pointer) {
	_, _, _ = procFwpmFreeMemory0.Call(uintptr(p))
}

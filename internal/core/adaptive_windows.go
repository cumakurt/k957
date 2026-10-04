//go:build windows

package core

import (
	"context"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func platformProcessExecutables(ctx context.Context) ([]ExecutableReference, string, error) {
	method := "Windows EnumProcesses / QueryFullProcessImageName / Tool Help native and 32-bit modules"
	pids := make([]uint32, 256)
	for {
		if e := ctx.Err(); e != nil {
			return nil, method, e
		}
		var returned uint32
		if e := windows.EnumProcesses(pids, &returned); e != nil {
			return nil, method, e
		}
		if int(returned) < len(pids)*4 {
			pids = pids[:int(returned)/4]
			break
		}
		pids = make([]uint32, len(pids)*2)
	}
	refs := []ExecutableReference{}
	for _, pid := range pids {
		if e := ctx.Err(); e != nil {
			return refs, method, e
		}
		if pid == 0 {
			continue
		}
		ref := ExecutableReference{PID: int(pid), Status: "observed"}
		h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if e == nil {
			buf := make([]uint16, 32768)
			n := uint32(len(buf))
			e = windows.QueryFullProcessImageName(h, 0, &buf[0], &n)
			if e == nil {
				ref.Path = windows.UTF16ToString(buf[:n])
			}
			closeErr := windows.CloseHandle(h)
			if e == nil {
				e = closeErr
			}
		}
		if e != nil {
			ref.Status, ref.Reason = "unavailable", e.Error()
		}
		refs = append(refs, ref)
		modules, moduleErr := windowsProcessModules(ctx, pid)
		refs = append(refs, modules...)
		if moduleErr != nil {
			if ctx.Err() != nil {
				return refs, method, ctx.Err()
			}
			refs = append(refs, ExecutableReference{PID: int(pid), Kind: "loaded_module", Status: "unavailable", Reason: moduleErr.Error()})
		}
	}
	return refs, method, nil
}

func windowsProcessModules(ctx context.Context, pid uint32) (refs []ExecutableReference, err error) {
	var snapshot windows.Handle
	// Loader churn can invalidate a snapshot. Keep retries finite so a changing
	// process cannot indefinitely prevent collection of other processes.
	for attempt := 0; attempt < 3; attempt++ {
		if err = ctx.Err(); err != nil {
			return
		}
		snapshot, err = windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
		if err != windows.ERROR_BAD_LENGTH {
			break
		}
	}
	if err != nil {
		return refs, fmt.Errorf("module snapshot: %w", err)
	}
	defer func() {
		if closeErr := windows.CloseHandle(snapshot); err == nil {
			err = closeErr
		}
	}()
	entry := windows.ModuleEntry32{Size: uint32(windows.SizeofModuleEntry32)}
	err = windows.Module32First(snapshot, &entry)
	for err == nil {
		if err = ctx.Err(); err != nil {
			return
		}
		name := windows.UTF16ToString(entry.ExePath[:])
		ref := ExecutableReference{PID: int(pid), Kind: "loaded_module", Path: name, Status: "observed",
			Module: &LoadedModuleReference{Name: windows.UTF16ToString(entry.Module[:]), BaseAddress: fmt.Sprintf("0x%x", entry.ModBaseAddr), ImageBytes: entry.ModBaseSize}}
		// The fixed MAX_PATH field cannot safely identify an unterminated path.
		terminated := false
		for _, ch := range entry.ExePath {
			if ch == 0 {
				terminated = true
				break
			}
		}
		if !terminated || !filepath.IsAbs(name) || entry.ProcessID != pid {
			ref.Status, ref.Reason = "unavailable", "incomplete module path or inconsistent process identity"
		}
		refs = append(refs, ref)
		entry = windows.ModuleEntry32{Size: uint32(windows.SizeofModuleEntry32)}
		err = windows.Module32Next(snapshot, &entry)
	}
	if err == windows.ERROR_NO_MORE_FILES {
		err = nil
	}
	return
}

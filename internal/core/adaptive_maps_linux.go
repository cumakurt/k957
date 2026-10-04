//go:build linux

package core

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Only executable file mappings expand logical acquisition. Anonymous mappings
// are retained in the separately acquired memory image, not guessed as paths.
func linuxProcessMappings(ctx context.Context, root string, pid int) ([]ExecutableReference, error) {
	file, err := os.Open(filepath.Join(root, strconv.Itoa(pid), "maps"))
	if err != nil {
		return nil, fmt.Errorf("read process mappings: %w", err)
	}
	defer file.Close()
	reader := bufio.NewReader(&contextReader{ctx: ctx, r: file})
	refs := []ExecutableReference{}
	seen := map[string]int{}
	for lineNumber := 1; ; lineNumber++ {
		line, readErr := reader.ReadString('\n')
		if len(line) > 0 {
			mapping, name, err := parseExecutableMapping(strings.TrimSuffix(line, "\n"), lineNumber)
			if err != nil {
				return refs, fmt.Errorf("process maps line %d: %w", lineNumber, err)
			}
			if name != "" {
				key := mapping.Device + ":" + mapping.Inode + ":" + name
				if index, ok := seen[key]; ok {
					refs[index].Mappings = append(refs[index].Mappings, mapping)
				} else {
					ref := ExecutableReference{PID: pid, Kind: "executable_mapping", Path: name, Status: "observed", Mappings: []ExecutableMapping{mapping}}
					if err := mappedFileIdentity(name, mapping); err != nil {
						ref.Status, ref.Reason = "unavailable", err.Error()
					}
					seen[key] = len(refs)
					refs = append(refs, ref)
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return refs, nil
			}
			return refs, fmt.Errorf("read process mappings: %w", readErr)
		}
	}
}

func parseExecutableMapping(line string, lineNumber int) (ExecutableMapping, string, error) {
	var fields [5]string
	for i := range fields {
		line = strings.TrimLeft(line, " \t")
		end := strings.IndexAny(line, " \t")
		if end < 0 {
			if i != len(fields)-1 || line == "" {
				return ExecutableMapping{}, "", errors.New("incomplete mapping fields")
			}
			fields[i], line = line, ""
		} else {
			fields[i], line = line[:end], line[end:]
		}
	}
	mapping := ExecutableMapping{Line: lineNumber, Address: fields[0], Permissions: fields[1], Offset: fields[2], Device: fields[3], Inode: fields[4]}
	start, end, ok := strings.Cut(mapping.Address, "-")
	first, e1 := strconv.ParseUint(start, 16, 64)
	last, e2 := strconv.ParseUint(end, 16, 64)
	_, e3 := strconv.ParseUint(mapping.Offset, 16, 64)
	major, minor, deviceOK := strings.Cut(mapping.Device, ":")
	_, e4 := strconv.ParseUint(major, 16, 32)
	_, e5 := strconv.ParseUint(minor, 16, 32)
	inode, e6 := strconv.ParseUint(mapping.Inode, 10, 64)
	perms := mapping.Permissions
	if !ok || !deviceOK || e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil || first >= last ||
		len(perms) != 4 || !strings.ContainsRune("r-", rune(perms[0])) || !strings.ContainsRune("w-", rune(perms[1])) ||
		!strings.ContainsRune("x-", rune(perms[2])) || !strings.ContainsRune("ps", rune(perms[3])) {
		return mapping, "", errors.New("invalid mapping fields")
	}
	name := strings.TrimLeft(line, " \t")
	if perms[2] != 'x' || inode == 0 || !filepath.IsAbs(name) {
		return mapping, "", nil
	}
	return mapping, name, nil
}

func mappedFileIdentity(name string, mapping ExecutableMapping) error {
	if strings.HasSuffix(name, " (deleted)") {
		return errors.New("mapped file was deleted; retain its references for memory examination")
	}
	// proc_pid_maps(5): \012 cannot be distinguished from a literal pathname
	// sequence. Do not silently choose either possible acquisition source.
	if strings.Contains(name, `\012`) {
		return errors.New("ambiguous escaped mapping pathname; inspect original process maps")
	}
	info, err := os.Stat(name)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok {
		return errors.New("mapped path is not an identifiable regular file")
	}
	majorText, minorText, _ := strings.Cut(mapping.Device, ":")
	major, _ := strconv.ParseUint(majorText, 16, 32)
	minor, _ := strconv.ParseUint(minorText, 16, 32)
	inode, _ := strconv.ParseUint(mapping.Inode, 10, 64)
	if uint64(unix.Major(uint64(stat.Dev))) != major || uint64(unix.Minor(uint64(stat.Dev))) != minor || stat.Ino != inode {
		return errors.New("mapped device/inode differs from current path; file replacement or mount namespace may differ")
	}
	return nil
}

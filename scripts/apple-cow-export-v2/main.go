// Export ordinary files from an explicitly selected APFS volume and COW delta.
package main

import (
	"codex/cowreader"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

type dirs []string

func (d *dirs) String() string     { return strings.Join(*d, ",") }
func (d *dirs) Set(s string) error { *d = append(*d, s); return nil }
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func clean(p string) bool {
	return strings.HasPrefix(p, "/") && path.Clean(p) == p && !strings.ContainsRune(p, 0)
}
func uuidString(u [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[:4], u[4:6], u[6:8], u[8:10], u[10:])
}
func find(parent *apfs.FileEntry, name string) (*apfs.FileEntry, error) {
	count, err := parent.NumberOfSubFileEntries()
	if err != nil {
		return nil, err
	}
	for i := 0; i < count; i++ {
		child, err := parent.SubFileEntryByIndex(i)
		if err != nil {
			return nil, err
		}
		actual, err := child.UTF8Name()
		if err != nil {
			return nil, err
		}
		if actual == name {
			return child, nil
		}
	}
	return nil, nil
}

func main() {
	manifest := flag.String("manifest", "", "qualified source-backed COW manifest")
	output := flag.String("out", "", "new output directory")
	selector := flag.String("volume", "role:system", "explicit System/Data role or volume UUID/name/index selector")
	expectedRole := flag.String("expected-role", "", "optional required system/data role")
	guestMount := flag.String("guest-mount", "", "declared guest mount prefix; required for Data (e.g. /private/var)")
	requireDirs := flag.Bool("require-directories", false, "fail if a requested volume-relative directory is absent")
	maxBytes := flag.Uint64("max-bytes", 512<<20, "maximum exported ordinary-file bytes")
	maxFiles := flag.Int("max-files", 10000, "maximum exported regular files")
	var selected dirs
	flag.Var(&selected, "dir", "clean volume-relative absolute directory; repeatable")
	flag.Parse()
	if *manifest == "" || *output == "" || *selector == "" || *maxFiles <= 0 || *maxBytes == 0 || flag.NArg() != 0 {
		must(fmt.Errorf("manifest/output/explicit volume and positive budgets required"))
	}
	reader, err := cowreader.Open(*manifest)
	must(err)
	defer reader.Close()
	container, err := apfs.Open(reader, nil)
	must(err)
	volume, err := container.VolumeBySelector(*selector)
	must(err)
	role, err := volume.Role()
	must(err)
	if role != apfs.VolumeRoleSystem && role != apfs.VolumeRoleData {
		must(fmt.Errorf("selected volume role must be System or Data"))
	}
	roleName := apfs.VolumeRoleString(role)
	if *expectedRole != "" && *expectedRole != roleName {
		must(fmt.Errorf("selected role %s differs from expected role %s", roleName, *expectedRole))
	}
	if role == apfs.VolumeRoleData && *guestMount == "" {
		must(fmt.Errorf("Data requires an explicit guest mount prefix; paths are volume-relative"))
	}
	if *guestMount == "" {
		*guestMount = "/"
	}
	if !clean(*guestMount) {
		must(fmt.Errorf("guest mount prefix must be clean and absolute"))
	}
	if len(selected) == 0 {
		if role == apfs.VolumeRoleSystem {
			selected = dirs{"/private/var/db/diagnostics", "/private/var/db/uuidtext"}
		} else {
			selected = dirs{"/db/diagnostics", "/db/uuidtext"}
		}
	}
	mappings := []map[string]string{}
	for _, p := range selected {
		if !clean(p) || p == "/" {
			must(fmt.Errorf("select a clean volume-relative directory other than root: %q", p))
		}
		if role == apfs.VolumeRoleData && *guestMount != "/" && (p == *guestMount || strings.HasPrefix(p, *guestMount+"/")) {
			must(fmt.Errorf("Data path %q includes guest mount prefix; supply volume-relative path", p))
		}
		mappings = append(mappings, map[string]string{"volume_path": p, "guest_path": path.Join(*guestMount, p)})
	}
	name, err := volume.UTF8Name()
	must(err)
	id, err := volume.Identifier()
	must(err)
	must(os.Mkdir(*output, 0700))
	var total uint64
	files := 0
	records := []map[string]any{}
	var walk func(*apfs.FileEntry, string)
	walk = func(e *apfs.FileEntry, p string) {
		mode, err := e.FileMode()
		must(err)
		target := filepath.Join(*output, strings.TrimPrefix(p, "/"))
		switch mode & 0170000 {
		case 0040000:
			must(os.MkdirAll(target, 0700))
			count, err := e.NumberOfSubFileEntries()
			must(err)
			for i := 0; i < count; i++ {
				child, err := e.SubFileEntryByIndex(i)
				must(err)
				childName, err := child.UTF8Name()
				must(err)
				if childName == "." || childName == ".." || filepath.Base(childName) != childName || strings.ContainsRune(childName, 0) {
					must(fmt.Errorf("unsafe APFS name %q", childName))
				}
				walk(child, p+"/"+childName)
			}
		case 0100000:
			size, err := e.DataSize()
			must(err)
			compressed, err := e.HasExtendedAttributeByName("com.apple.decmpfs")
			must(err)
			if compressed {
				must(fmt.Errorf("compressed log file unsupported: %s", p))
			}
			if size < 0 || files >= *maxFiles || uint64(size) > *maxBytes-total {
				must(fmt.Errorf("export budget exceeded at %s", p))
			}
			must(os.MkdirAll(filepath.Dir(target), 0700))
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			must(err)
			h := sha256.New()
			n, err := io.Copy(io.MultiWriter(f, h), io.NewSectionReader(e, 0, int64(size)))
			closeErr := f.Close()
			must(err)
			must(closeErr)
			if n != size {
				must(fmt.Errorf("short file read %s", p))
			}
			total += uint64(size)
			files++
			records = append(records, map[string]any{"path": p, "guest_path": path.Join(*guestMount, p), "size": size, "sha256": hex.EncodeToString(h.Sum(nil))})
		default:
			records = append(records, map[string]any{"path": p, "skipped_mode": fmt.Sprintf("%06o", mode)})
		}
	}
	for _, p := range selected {
		e, err := volume.RootDirectory()
		must(err)
		for _, part := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
			e, err = find(e, part)
			must(err)
			if e == nil {
				break
			}
		}
		if e == nil {
			if *requireDirs {
				must(fmt.Errorf("requested volume-relative directory missing: %s", p))
			}
			records = append(records, map[string]any{"path": p, "missing": true})
			continue
		}
		mode, err := e.FileMode()
		must(err)
		if mode&0170000 != 0040000 {
			must(fmt.Errorf("requested directory is not a directory: %s", p))
		}
		walk(e, p)
	}
	report := map[string]any{"manifest": *manifest, "volume_selector": *selector, "volume_name": name, "volume_uuid": uuidString(id), "volume_role": roleName, "volume_role_raw": role, "guest_mount_prefix": *guestMount, "path_namespace": "volume-relative absolute paths; guest paths are declared mappings, not mounted-guest proof", "path_mappings": mappings, "directories": selected, "files": files, "bytes": total, "records": records, "filesystem_consistency": "captured paused/crash-consistent; not fsck-clean", "daemon_os_log_decoded": false}
	raw, err := json.MarshalIndent(report, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(*output, "export-report.json"), append(raw, '\n'), 0600))
	fmt.Printf("Exported %d files, %d bytes from %s (%s); no daemon decoding claim\n", files, total, name, roleName)
}

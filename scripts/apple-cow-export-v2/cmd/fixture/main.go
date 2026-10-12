// Build a sparse, owned host fixture. Never launched as a guest.
package main

import (
	"fmt"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"os"
)

func dir(name string, children ...*apfswrite.Entry) *apfswrite.Entry {
	return &apfswrite.Entry{Name: name, Mode: os.ModeDir | 0755, Children: children}
}
func file(name, contents string) *apfswrite.Entry {
	return &apfswrite.Entry{Name: name, Mode: 0600, Data: []byte(contents)}
}
func main() {
	if len(os.Args) != 2 {
		panic("fixture output path required")
	}
	f, err := os.OpenFile(os.Args[1], os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	systemID := [16]byte{0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55}
	dataID := [16]byte{0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xcc, 0xcc, 0xdd, 0xdd, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee}
	system := dir("", dir("private", dir("var", dir("db", dir("diagnostics", file("probe.tracev3", "SYSTEM-CONTROL-ORDINARY-FILE\n")), dir("uuidtext", file("probe", "SYSTEM-UUIDTEXT\n"))))))
	data := dir("", dir("db", dir("diagnostics", file("probe.tracev3", "DATA-CONTROL-ORDINARY-FILE\n")), dir("uuidtext", file("probe", "DATA-UUIDTEXT\n"))), dir("private", dir("var", dir("db", dir("diagnostics", file("decoy", "WRONG-GUEST-PATH-DECOY\n"))))))
	const size = 513 << 20
	err = apfswrite.CreateContainer(f, size, &apfswrite.CreateOptions{Volumes: []apfswrite.VolumeSpec{{Name: "FixtureSystem", UUID: systemID, Role: apfs.VolumeRoleSystem, Root: system, CaseSensitive: true}, {Name: "FixtureData", UUID: dataID, Role: apfs.VolumeRoleData, Root: data, CaseSensitive: true}}})
	if err != nil {
		panic(err)
	}
	if err := f.Sync(); err != nil {
		panic(err)
	}
	info, err := f.Stat()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Owned sparse host fixture: %d bytes,2 distinct volumes; never a guest\n", info.Size())
}

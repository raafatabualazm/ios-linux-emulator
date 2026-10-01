package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

func diffRecord(off uint64, data []byte) []byte {
	result := make([]byte, 12+len(data))
	binary.LittleEndian.PutUint64(result, off)
	binary.LittleEndian.PutUint32(result[8:], uint32(len(data)))
	copy(result[12:], data)
	return result
}

func fixture(t *testing.T) (*os.File, []byte, []extent, []byte) {
	t.Helper()
	logical := []byte("abcdefgh")
	image := bytes.Repeat([]byte{0xa5}, 5*blockSize)
	exts := []extent{{logical: 0, phys: blockSize, size: 4}, {logical: 4, phys: 3 * blockSize, size: 4}}
	copy(image[blockSize:], logical[:4])
	copy(image[3*blockSize:], logical[4:])
	path := filepath.Join(t.TempDir(), "image.raw")
	if err := os.WriteFile(path, image, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f, image, exts, logical
}

func assertImage(t *testing.T, f *os.File, want []byte) {
	t.Helper()
	got, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("image bytes changed unexpectedly")
	}
}

func TestInvalidDiffDoesNotWriteValidPrefix(t *testing.T) {
	valid := diffRecord(0, []byte("X"))
	largeLength := make([]byte, 12)
	binary.LittleEndian.PutUint32(largeLength[8:], math.MaxUint32)
	cases := map[string][]byte{
		"truncated header":  append(append([]byte{}, valid...), 1),
		"truncated payload": append(append([]byte{}, valid...), diffRecord(4, []byte("XX"))[:13]...),
		"out of bounds":     append(append([]byte{}, valid...), diffRecord(8, []byte("X"))...),
		"unsigned offset":   append(append([]byte{}, valid...), diffRecord(math.MaxUint64, []byte("X"))...),
		"signed overflow":   append(append([]byte{}, valid...), diffRecord(math.MaxInt64, []byte("XX"))...),
		"huge length":       append(append([]byte{}, valid...), largeLength...),
		"overlap":           append(append([]byte{}, valid...), diffRecord(0, []byte("Y"))...),
		"unsorted":          append(diffRecord(4, []byte("X")), diffRecord(0, []byte("Y"))...),
		"empty record":      append(append([]byte{}, valid...), diffRecord(4, nil)...),
	}
	for name, diff := range cases {
		t.Run(name, func(t *testing.T) {
			f, before, exts, logical := fixture(t)
			if _, err := applyDiff(f, bytes.NewReader(logical), diff, uint64(len(logical)), exts, 0); err == nil {
				t.Fatal("invalid diff accepted")
			}
			assertImage(t, f, before)
		})
	}
}

func TestMappingMismatchDoesNotWrite(t *testing.T) {
	f, before, exts, logical := fixture(t)
	logical[0] = '!'
	if _, err := applyDiff(f, bytes.NewReader(logical), diffRecord(0, []byte("X")), 8, exts, 0); err == nil {
		t.Fatal("incorrect mapping accepted")
	}
	assertImage(t, f, before)
}

func TestSparseExtentDoesNotWriteSuperblock(t *testing.T) {
	for _, flags := range []uint32{0, 1} {
		f, before, _, logical := fixture(t)
		exts := []extent{{phys: 0, size: uint64(len(logical)), flags: flags}}
		if _, err := applyDiff(f, bytes.NewReader(logical), diffRecord(0, []byte("X")), 8, exts, 0); err == nil {
			t.Fatal("sparse extent accepted")
		}
		if _, _, err := mapLogical(exts, 0); err == nil {
			t.Fatal("hole can be mapped for writing")
		}
		assertImage(t, f, before)
	}
}

func TestApplyDiffSplitsExtentsAndPreservesOtherBytes(t *testing.T) {
	f, before, exts, logical := fixture(t)
	records, err := applyDiff(f, bytes.NewReader(logical), diffRecord(2, []byte("WXYZ")), 8, exts, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records", len(records))
	}
	want := append([]byte{}, before...)
	copy(want[blockSize+2:], []byte("WX"))
	copy(want[3*blockSize:], []byte("YZ"))
	assertImage(t, f, want)
}

func TestContainerBaseIsAppliedOnce(t *testing.T) {
	exts := []extent{{phys: blockSize, size: 8}}
	_, writes, err := planWrites(diffRecord(3, []byte("XY")), 8, exts, 2*blockSize, 5*blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(writes) != 1 || writes[0].off != 3*blockSize+3 {
		t.Fatalf("wrong image offset: %+v", writes)
	}
}

func TestRejectInvalidAndOverflowingExtents(t *testing.T) {
	cases := map[string]struct {
		exts            []extent
		size            uint64
		base, imageSize int64
	}{
		"negative base":           {[]extent{{phys: blockSize, size: 8}}, 8, -1, 5 * blockSize},
		"overflowing file size":   {[]extent{{phys: blockSize, size: 8}}, math.MaxUint64, 0, 5 * blockSize},
		"overflowing extent size": {[]extent{{phys: blockSize, size: math.MaxUint64}}, 8, 0, 5 * blockSize},
		"physical base overflow":  {[]extent{{phys: math.MaxInt64 - 4095, size: 8}}, 8, 2 * blockSize, math.MaxInt64},
		"unsupported flags":       {[]extent{{phys: blockSize, size: 8, flags: 1}}, 8, 0, 5 * blockSize},
		"negative physical":       {[]extent{{phys: -blockSize, size: 8}}, 8, 0, 5 * blockSize},
		"logical gap":             {[]extent{{phys: blockSize, size: 4}, {logical: 5, phys: 3 * blockSize, size: 4}}, 8, 0, 5 * blockSize},
		"missing coverage":        {[]extent{{phys: blockSize, size: 4}}, 8, 0, 5 * blockSize},
		"outside image":           {[]extent{{phys: 5 * blockSize, size: 8}}, 8, 0, 5 * blockSize},
		"shared physical range":   {[]extent{{phys: blockSize, size: 4}, {logical: 4, phys: blockSize, size: 4}}, 8, 0, 5 * blockSize},
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := planWrites(diffRecord(0, []byte("X")), value.size, value.exts, value.base, value.imageSize); err == nil {
				t.Fatal("invalid extent accepted")
			}
		})
	}
}

type incompleteReader struct{ err error }

func (r incompleteReader) ReadAt(p []byte, off int64) (int, error) { return 0, r.err }

func TestShortReadsCannotConfirmZeroBytes(t *testing.T) {
	for _, err := range []error{nil, io.EOF} {
		reader := incompleteReader{err}
		if readFullAt(reader, make([]byte, 4), 0) == nil {
			t.Fatal("short read accepted")
		}
		if confirmRecords(reader, []record{{data: []byte{0, 0, 0, 0}}}) == nil {
			t.Fatal("short read confirmed zero patch")
		}
		image := make([]byte, 2*blockSize)
		exts := []extent{{phys: blockSize, size: 4}}
		if verifyData(bytes.NewReader(image), reader, 0, 4, int64(len(image)), exts) == nil {
			t.Fatal("short read passed mapping verification")
		}
	}
}

func TestExtractionRejectsImageAliasesWithoutTruncating(t *testing.T) {
	for _, alias := range []string{"same", "symlink", "hardlink"} {
		t.Run(alias, func(t *testing.T) {
			f, before, _, _ := fixture(t)
			dest := f.Name()
			if alias != "same" {
				dest = filepath.Join(filepath.Dir(f.Name()), alias)
				var err error
				if alias == "symlink" {
					err = os.Symlink(f.Name(), dest)
				} else {
					err = os.Link(f.Name(), dest)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			out, err := openOutput(f, dest)
			if err == nil {
				out.Close()
				t.Fatal("source image alias accepted")
			}
			assertImage(t, f, before)
		})
	}
}

func TestRejectUnsupportedAPFSMetadataBeforeOffsetConversion(t *testing.T) {
	cases := map[string]*apfs.FileEntry{
		"compressed": {Inode: &apfs.Inode{BSDFlags: apfs.BSDFlagCompressed},
			FileExtents: []*apfs.FileExtent{{PhysicalBlockNumber: 1, DataSize: 8}}},
		"encrypted": {Inode: &apfs.Inode{},
			FileExtents: []*apfs.FileExtent{{PhysicalBlockNumber: 1, DataSize: 8, EncryptionIdentifier: 7}}},
		"physical multiplication overflow": {Inode: &apfs.Inode{},
			FileExtents: []*apfs.FileExtent{{PhysicalBlockNumber: math.MaxUint64, DataSize: 8}}},
		"sparse logical gap": {Inode: &apfs.Inode{},
			FileExtents: []*apfs.FileExtent{{LogicalOffset: 1, PhysicalBlockNumber: 1, DataSize: 8}}},
	}
	for name, file := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := readExtents(file); err == nil {
				t.Fatal("unsupported APFS metadata accepted")
			}
		})
	}
	ordinary := &apfs.FileEntry{Inode: &apfs.Inode{},
		FileExtents: []*apfs.FileExtent{{PhysicalBlockNumber: 1, DataSize: 8}}}
	exts, err := readExtents(ordinary)
	if err != nil || len(exts) != 1 || exts[0].phys != blockSize || exts[0].logical != 0 {
		t.Fatalf("ordinary extent failed: %+v, %v", exts, err)
	}
}

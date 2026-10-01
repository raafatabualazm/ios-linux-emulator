package main

// extent-probe applies sorted same-size overwrites to verified extents in an
// offline raw APFS image. It does not allocate blocks or update metadata.
// Diff records: little-endian uint64 logical offset, uint32 length, data[length].
// See README.md for supported image constraints and recovery requirements.
import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

const chunkSize = 1 << 20
const blockSize = 4096 // go-apfs-v2 v0.9.0's ExtentByIndex assumes this size.

type fileData interface {
	io.ReaderAt
	Size() (uint64, error)
	NumberOfExtents() (int, error)
	ExtentByIndex(int) (int64, uint64, uint32, error)
}

type extent struct {
	logical int64
	phys    int64
	size    uint64
	flags   uint32
}
type record struct {
	off  int64
	data []byte
}
type imageWrite struct {
	off  int64
	data []byte
}

func main() {
	img := flag.String("img", "", "raw APFS image file")
	base := flag.Int64("base", 0, "byte offset of the APFS container")
	vol := flag.String("vol", "0", "volume selector")
	extract := flag.String("extract", "", "volpath=dest : write a file out")
	patch := flag.String("patch", "", "volpath=diff : apply a same-size diff")
	flag.Parse()
	if *img == "" {
		usage()
	}
	if *base < 0 {
		fatal(fmt.Errorf("-base must be nonnegative"))
	}
	if *extract != "" && *patch != "" {
		fatal(fmt.Errorf("-extract and -patch are separate modes"))
	}
	mode := *extract
	if *patch != "" {
		mode = *patch
	}
	if mode == "" {
		if flag.NArg() == 0 {
			usage()
		}
		if err := runVerify(*img, *base, *vol, flag.Args()); err != nil {
			fatal(err)
		}
		return
	}
	vpath, hostpath, ok := strings.Cut(mode, "=")
	if !ok || vpath == "" || hostpath == "" {
		fatal(fmt.Errorf("mode wants a nonempty volpath=hostpath"))
	}
	f, fe, err := lookupImage(*img, *base, *vol, vpath)
	if err != nil {
		fatal(err)
	}
	if *extract != "" {
		err = doExtract(f, vpath, hostpath, fe)
	} else {
		err = doPatch(f, *img, *base, *vol, vpath, hostpath, fe)
	}
	closeErr := f.Close()
	if err != nil {
		fatal(err)
	}
	if closeErr != nil {
		fatal(closeErr)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  extent-probe -img FILE [-base OFF] [-vol SEL] /path/in/volume ...
  extent-probe -img FILE [-base OFF] [-vol SEL] -extract /path/in/vol=dest
  extent-probe -img FILE [-base OFF] [-vol SEL] -patch /path/in/vol=diff`)
	os.Exit(2)
}

func runVerify(img string, base int64, vol string, paths []string) error {
	f, err := os.Open(img)
	if err != nil {
		return err
	}
	defer f.Close()
	root, err := openRoot(f, base, vol)
	if err != nil {
		return err
	}
	var failed int
	for _, path := range paths {
		fe, err := lookupPath(root, path)
		if err == nil {
			err = verify(f, base, path, fe)
		}
		if err != nil {
			fmt.Printf("%s: FAIL: %v\n", path, err)
			failed++
		}
	}
	if failed != 0 {
		return fmt.Errorf("%d of %d paths failed verification", failed, len(paths))
	}
	fmt.Printf("all %d paths verified: logical bytes == raw image bytes\n", len(paths))
	return nil
}

func verify(f *os.File, base int64, path string, fe fileData) error {
	size, err := fe.Size()
	if err != nil {
		return fmt.Errorf("size: %w", err)
	}
	exts, err := readExtents(fe)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if err := verifyData(f, fe, base, size, info.Size(), exts); err != nil {
		return err
	}
	fmt.Printf("%s: verified %d bytes across %d extents\n", path, size, len(exts))
	return nil
}

// Check the full layout before reads or writes, including untouched extents.
func validateExtents(exts []extent, size uint64, imageSize, base int64) error {
	if size > math.MaxInt64 || imageSize < 0 || base < 0 || base > imageSize {
		return fmt.Errorf("invalid file size, image size or container offset")
	}
	if len(exts) == 0 {
		return fmt.Errorf("no extents: inline or compressed files cannot be patched")
	}
	var covered int64
	for i, e := range exts {
		if e.phys <= 0 || e.phys%blockSize != 0 || e.flags != 0 {
			return fmt.Errorf("extent %d: sparse or unsupported physical mapping", i)
		}
		if e.logical != covered || e.size == 0 || e.size > uint64(math.MaxInt64-covered) {
			return fmt.Errorf("extent %d: invalid, overflowing or noncontiguous logical range", i)
		}
		if i > 0 && uint64(covered) >= size {
			return fmt.Errorf("extent %d starts beyond file EOF", i)
		}
		available := imageSize - base
		if e.phys > available || e.size > uint64(available-e.phys) {
			return fmt.Errorf("extent %d: physical range is outside the image", i)
		}
		covered += int64(e.size)
	}
	if uint64(covered) < size {
		return fmt.Errorf("extents cover %d of %d file bytes", covered, size)
	}
	physical := append([]extent(nil), exts...)
	sort.Slice(physical, func(i, j int) bool { return physical[i].phys < physical[j].phys })
	for i := 1; i < len(physical); i++ {
		previous := physical[i-1]
		if physical[i].phys < previous.phys+int64(previous.size) {
			return fmt.Errorf("file extents overlap in the image")
		}
	}
	return nil
}

func readFullAt(reader io.ReaderAt, data []byte, off int64) error {
	n, err := reader.ReadAt(data, off)
	if n != len(data) {
		return fmt.Errorf("short read at %d: got %d want %d: %w", off, n, len(data), io.ErrUnexpectedEOF)
	}
	if err != nil && err != io.EOF {
		return err
	}
	return nil
}

func verifyData(raw, logical io.ReaderAt, base int64, size uint64, imageSize int64, exts []extent) error {
	if err := validateExtents(exts, size, imageSize, base); err != nil {
		return err
	}
	for i, e := range exts {
		end := min(e.logical+int64(e.size), int64(size))
		for off := e.logical; off < end; {
			n := min(int64(chunkSize), end-off)
			physical := base + e.phys + (off - e.logical)
			a, b := make([]byte, n), make([]byte, n)
			if err := readFullAt(raw, a, physical); err != nil {
				return fmt.Errorf("extent %d raw read: %w", i, err)
			}
			if err := readFullAt(logical, b, off); err != nil {
				return fmt.Errorf("extent %d APFS read: %w", i, err)
			}
			if !bytes.Equal(a, b) {
				return fmt.Errorf("extent %d: raw and logical bytes differ at %d", i, off)
			}
			off += n
		}
	}
	return nil
}

// Open without truncating, then compare actual identities to catch all aliases.
func openOutput(image *os.File, dest string) (*os.File, error) {
	sourceInfo, err := image.Stat()
	if err != nil {
		return nil, err
	}
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	outputInfo, err := out.Stat()
	if err == nil && os.SameFile(sourceInfo, outputInfo) {
		err = fmt.Errorf("extraction destination aliases the source image")
	}
	if err == nil && !outputInfo.Mode().IsRegular() {
		err = fmt.Errorf("extraction destination must be a regular file")
	}
	if err == nil {
		err = out.Truncate(0)
	}
	if err != nil {
		out.Close()
		return nil, err
	}
	return out, nil
}

func doExtract(image *os.File, vpath, dest string, fe fileData) error {
	size, err := fe.Size()
	if err != nil {
		return err
	}
	if size > math.MaxInt64 {
		return fmt.Errorf("file size exceeds supported offsets")
	}
	out, err := openOutput(image, dest)
	if err != nil {
		return err
	}
	defer out.Close()
	buf := make([]byte, chunkSize)
	for done := int64(0); done < int64(size); {
		n := min(int64(chunkSize), int64(size)-done)
		if err := readFullAt(fe, buf[:n], done); err != nil {
			return err
		}
		if _, err := out.Write(buf[:n]); err != nil {
			return err
		}
		done += n
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	fmt.Printf("extracted %s -> %s (%d bytes)\n", vpath, dest, size)
	return nil
}

func parseDiff(diff []byte, size uint64) ([]record, error) {
	if size > math.MaxInt64 {
		return nil, fmt.Errorf("file size exceeds supported offsets")
	}
	var records []record
	var previousEnd uint64
	for pos := 0; pos < len(diff); {
		if len(diff)-pos < 12 {
			return nil, fmt.Errorf("diff truncated at %d: incomplete header", pos)
		}
		off := binary.LittleEndian.Uint64(diff[pos:])
		n := uint64(binary.LittleEndian.Uint32(diff[pos+8:]))
		pos += 12
		if n == 0 || n > uint64(len(diff)-pos) {
			return nil, fmt.Errorf("empty or truncated payload at %d", pos)
		}
		if off > size || n > size-off || off < previousEnd {
			return nil, fmt.Errorf("range at %d is out of bounds, unsorted or overlapping", pos)
		}
		end := pos + int(n) // n <= len(diff)-pos, safe on 32-bit hosts too.
		records = append(records, record{off: int64(off), data: diff[pos:end]})
		previousEnd = off + n
		pos = end
	}
	return records, nil
}

func planWrites(diff []byte, size uint64, exts []extent, base, imageSize int64) ([]record, []imageWrite, error) {
	if err := validateExtents(exts, size, imageSize, base); err != nil {
		return nil, nil, err
	}
	records, err := parseDiff(diff, size)
	if err != nil {
		return nil, nil, err
	}
	var writes []imageWrite
	for _, r := range records {
		for written := 0; written < len(r.data); {
			phys, room, err := mapLogical(exts, r.off+int64(written))
			if err != nil {
				return nil, nil, err
			}
			n := min(int64(len(r.data)-written), room)
			if n <= 0 {
				return nil, nil, fmt.Errorf("extent mapping made no progress")
			}
			end := written + int(n)
			writes = append(writes, imageWrite{off: base + phys, data: r.data[written:end]})
			written = end
		}
	}
	return records, writes, nil
}

// Invalid input and mapping mismatches leave the image untouched. I/O failures
// during writes still require the Python helper's saved undo data.
func applyDiff(f *os.File, logical io.ReaderAt, diff []byte, size uint64, exts []extent, base int64) ([]record, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	records, writes, err := planWrites(diff, size, exts, base, info.Size())
	if err != nil {
		return nil, err
	}
	if err := verifyData(f, logical, base, size, info.Size(), exts); err != nil {
		return nil, err
	}
	for _, write := range writes {
		n, err := f.WriteAt(write.data, write.off)
		if err != nil {
			return nil, fmt.Errorf("write at image offset %d: %w", write.off, err)
		}
		if n != len(write.data) {
			return nil, io.ErrShortWrite
		}
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	return records, nil
}

func doPatch(source *os.File, img string, base int64, vol, vpath, diffPath string, fe fileData) error {
	size, err := fe.Size()
	if err != nil {
		return err
	}
	exts, err := readExtents(fe)
	if err != nil {
		return err
	}
	diff, err := os.ReadFile(diffPath)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(img, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	before, err := source.Stat()
	if err != nil {
		return err
	}
	current, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, current) || !current.Mode().IsRegular() {
		return fmt.Errorf("image identity changed or image is not a regular raw file")
	}
	records, err := applyDiff(f, fe, diff, size, exts, base)
	if err != nil {
		return err
	}
	freshFile, fresh, err := lookupImage(img, base, vol, vpath)
	if err != nil {
		return fmt.Errorf("reopen patched file: %w", err)
	}
	defer freshFile.Close()
	if err := confirmRecords(fresh, records); err != nil {
		return err
	}
	fmt.Printf("patched %s: confirmed %d records through APFS\n", vpath, len(records))
	return f.Close()
}

func confirmRecords(fresh io.ReaderAt, records []record) error {
	for _, r := range records {
		for done := 0; done < len(r.data); {
			n := min(chunkSize, len(r.data)-done)
			got := make([]byte, n)
			if err := readFullAt(fresh, got, r.off+int64(done)); err != nil {
				return fmt.Errorf("read back: %w", err)
			}
			if !bytes.Equal(got, r.data[done:done+n]) {
				return fmt.Errorf("patch did not read back at %d", r.off+int64(done))
			}
			done += n
		}
	}
	return nil
}

func mapLogical(exts []extent, logical int64) (int64, int64, error) {
	if logical < 0 {
		return 0, 0, fmt.Errorf("negative logical offset")
	}
	for _, e := range exts {
		if e.logical < 0 || e.size > math.MaxInt64 || logical < e.logical {
			continue
		}
		within := logical - e.logical
		if uint64(within) < e.size {
			if e.phys <= 0 || e.flags != 0 || e.phys > math.MaxInt64-within {
				return 0, 0, fmt.Errorf("sparse, unsupported or overflowing physical mapping")
			}
			return e.phys + within, int64(e.size) - within, nil
		}
	}
	return 0, 0, fmt.Errorf("logical offset %d has no extent", logical)
}

func readExtents(fe fileData) ([]extent, error) {
	count, err := fe.NumberOfExtents()
	if err != nil || count < 0 {
		return nil, fmt.Errorf("invalid extent count %d: %v", count, err)
	}
	if actual, ok := fe.(*apfs.FileEntry); ok {
		flags, err := actual.BSDFlags()
		if err != nil {
			return nil, err
		}
		if flags&apfs.BSDFlagCompressed != 0 {
			return nil, fmt.Errorf("compressed files cannot be patched in place")
		}
	}
	exts := make([]extent, 0, count)
	var logical int64
	for i := 0; i < count; i++ {
		if actual, ok := fe.(*apfs.FileEntry); ok {
			raw := actual.FileExtents[i]
			if raw == nil || raw.LogicalOffset != uint64(logical) || raw.PhysicalBlockNumber > math.MaxInt64/blockSize {
				return nil, fmt.Errorf("extent %d: noncontiguous or overflowing APFS extent", i)
			}
			if raw.EncryptionIdentifier != 0 {
				return nil, fmt.Errorf("extent %d: encrypted extents are unsupported", i)
			}
		}
		phys, size, flags, err := fe.ExtentByIndex(i)
		if err != nil {
			return nil, fmt.Errorf("extent %d: %w", i, err)
		}
		if size > uint64(math.MaxInt64-logical) {
			return nil, fmt.Errorf("extent %d: logical range overflows", i)
		}
		exts = append(exts, extent{logical: logical, phys: phys, size: size, flags: flags})
		logical += int64(size)
	}
	return exts, nil
}

func openRoot(f *os.File, base int64, vol string) (*apfs.FileEntry, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || base < 0 || info.Size() < blockSize || base > info.Size()-blockSize {
		return nil, fmt.Errorf("image must be a regular raw file with a valid container offset")
	}
	container, err := apfs.Open(f, &apfs.OpenOptions{Offset: base})
	if err != nil {
		return nil, fmt.Errorf("open container at %d: %w", base, err)
	}
	if container.IOHandle.BlockSize != blockSize {
		return nil, fmt.Errorf("only 4096-byte APFS blocks are supported")
	}
	v, err := container.VolumeBySelector(vol)
	if err != nil {
		return nil, fmt.Errorf("volume %q: %w", vol, err)
	}
	root, err := v.RootDirectory()
	if err != nil {
		return nil, fmt.Errorf("root directory: %w", err)
	}
	return root, nil
}

func lookupImage(img string, base int64, vol, path string) (*os.File, *apfs.FileEntry, error) {
	f, err := os.Open(img)
	if err != nil {
		return nil, nil, err
	}
	root, err := openRoot(f, base, vol)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	fe, err := lookupPath(root, path)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, fe, nil
}

func lookupPath(root *apfs.FileEntry, path string) (*apfs.FileEntry, error) {
	cur := root
	for _, part := range strings.Split(strings.Trim(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, err := cur.SubFileEntryByName(part)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", part, err)
		}
		cur = next
	}
	return cur, nil
}
func fatal(err error) { fmt.Fprintln(os.Stderr, "extent-probe:", err); os.Exit(1) }

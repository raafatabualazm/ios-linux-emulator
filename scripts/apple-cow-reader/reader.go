// Package cowreader presents a qualified private-memory delta as an io.ReaderAt.
// Neither the base image nor the captured delta is modified.
package cowreader

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

type Block struct {
	Offset int64 `json:"offset"`
	Size int64 `json:"size"`
	DeltaOffset int64 `json:"delta_offset"`
	SHA256 string `json:"sha256"`
}
type Manifest struct {
	Format string `json:"format"`
	Source string `json:"source"`
	SourceSHA256 string `json:"source_sha256"`
	SourceSize int64 `json:"source_size"`
	DeltaSHA256 string `json:"delta_sha256"`
	SavedBytes int64 `json:"saved_bytes"`
	PageSize int64 `json:"page_size"`
	Blocks []Block `json:"blocks"`
}
type Reader struct {
	base, delta *os.File
	manifest Manifest
}

func hash(f *os.File) (string, error) {
	h := sha256.New()
	stat, err := f.Stat(); if err != nil { return "", err }
	_, err = io.Copy(h, io.NewSectionReader(f, 0, stat.Size()))
	return hex.EncodeToString(h.Sum(nil)), err
}

// Open validates sizes, bounds, source/delta digests, block digests and ordering.
// The capture's crash consistency is unchanged; APFS validation remains separate.
func Open(manifestPath string) (*Reader, error) {
	raw, err := os.ReadFile(manifestPath); if err != nil { return nil, err }
	var m Manifest
	if err = json.Unmarshal(raw, &m); err != nil { return nil, err }
	if m.Format != "apple-modern-cow-delta-v1" || m.SourceSize <= 0 || m.SavedBytes < 0 || m.PageSize != 4096 {
		return nil, fmt.Errorf("unsupported or invalid COW manifest")
	}
	base, err := os.Open(m.Source); if err != nil { return nil, err }
	delta, err := os.Open(filepath.Join(filepath.Dir(manifestPath), "delta.bin"))
	if err != nil { base.Close(); return nil, err }
	r := &Reader{base: base, delta: delta, manifest: m}
	ok := false
	defer func() { if !ok { r.Close() } }()
	bstat, err := base.Stat(); if err != nil { return nil, err }
	dstat, err := delta.Stat(); if err != nil { return nil, err }
	if os.SameFile(bstat, dstat) || bstat.Size() != m.SourceSize || dstat.Size() != m.SavedBytes {
		return nil, fmt.Errorf("source/delta alias or size mismatch")
	}
	bhash, err := hash(base); if err != nil { return nil, err }
	dhash, err := hash(delta); if err != nil { return nil, err }
	if bhash != m.SourceSHA256 || dhash != m.DeltaSHA256 { return nil, fmt.Errorf("COW digest mismatch") }
	lastEnd, deltaEnd := int64(0), int64(0)
	for _, b := range m.Blocks {
		if b.Offset < lastEnd || b.Offset < 0 || b.Offset % m.PageSize != 0 || b.Size != m.PageSize ||
			b.Offset > m.SourceSize-b.Size || b.DeltaOffset != deltaEnd || b.DeltaOffset > m.SavedBytes-b.Size {
			return nil, fmt.Errorf("COW block order, alignment or bounds invalid")
		}
		buf := make([]byte, b.Size)
		if _, err = delta.ReadAt(buf, b.DeltaOffset); err != nil { return nil, err }
		digest := sha256.Sum256(buf)
		if hex.EncodeToString(digest[:]) != b.SHA256 { return nil, fmt.Errorf("COW block digest mismatch") }
		lastEnd, deltaEnd = b.Offset+b.Size, b.DeltaOffset+b.Size
	}
	if deltaEnd != m.SavedBytes { return nil, fmt.Errorf("unmapped COW delta bytes") }
	ok = true; return r, nil
}

func (r *Reader) ReadAt(buf []byte, offset int64) (int, error) {
	if offset < 0 { return 0, fmt.Errorf("negative offset") }
	if len(buf) == 0 { return 0, nil }
	n, err := r.base.ReadAt(buf, offset)
	end := offset + int64(n)
	if end < offset { return 0, fmt.Errorf("offset overflow") }
	blocks := r.manifest.Blocks
	index := sort.Search(len(blocks), func(i int) bool { return blocks[i].Offset + blocks[i].Size > offset })
	for ; index < len(blocks) && blocks[index].Offset < end; index++ {
		b := blocks[index]
		first, last := max(offset, b.Offset), min(end, b.Offset+b.Size)
		if _, readErr := r.delta.ReadAt(buf[first-offset:last-offset], b.DeltaOffset+first-b.Offset); readErr != nil {
			return 0, readErr
		}
	}
	return n, err
}

func (r *Reader) Close() error {
	first := r.base.Close(); second := r.delta.Close()
	if first != nil { return first }; return second
}

var _ io.ReaderAt = (*Reader)(nil)

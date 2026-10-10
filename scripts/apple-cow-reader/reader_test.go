package cowreader

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func digest(buf []byte) string { h := sha256.Sum256(buf); return hex.EncodeToString(h[:]) }

func TestOverlayAndRefusalOracles(t *testing.T) {
	dir := t.TempDir(); source := filepath.Join(dir, "source.bin"); path := filepath.Join(dir, "manifest.json")
	base := bytes.Repeat([]byte{0x31}, 3*4096); delta := bytes.Repeat([]byte{0x72}, 4096)
	if err := os.WriteFile(source, base, 0600); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(dir, "delta.bin"), delta, 0600); err != nil { t.Fatal(err) }
	m := Manifest{Format:"apple-modern-cow-delta-v1", Source:source, SourceSHA256:digest(base),
		SourceSize:int64(len(base)), DeltaSHA256:digest(delta), SavedBytes:4096, PageSize:4096,
		Blocks:[]Block{{Offset:4096, Size:4096, DeltaOffset:0, SHA256:digest(delta)}}}
	write := func(m Manifest) { raw, err := json.Marshal(m); if err != nil { t.Fatal(err) }; if err := os.WriteFile(path, raw, 0600); err != nil { t.Fatal(err) } }
	write(m); r, err := Open(path); if err != nil { t.Fatal(err) }; defer r.Close()
	expect := append([]byte(nil), base...); copy(expect[4096:8192], delta)
	for _, probe := range []struct{ off int64; size int }{{0,12288},{4090,20},{8180,20},{4096,4096},{12000,400},{12288,1},{0,0}} {
		got := make([]byte,probe.size); n,err := r.ReadAt(got,probe.off)
		wantN := min(probe.size, len(expect)-int(probe.off))
		if n != wantN || !bytes.Equal(got[:n],expect[int(probe.off):int(probe.off)+n]) { t.Fatalf("read at %d/%d differs",probe.off,probe.size) }
		if (wantN < probe.size) != (err == io.EOF) { t.Fatalf("EOF at %d: %v",probe.off,err) }
	}
	if _,err := r.ReadAt(make([]byte,1),-1); err == nil { t.Fatal("negative offset accepted") }
	oracles := []func(*Manifest){
		func(m *Manifest){m.SourceSHA256="wrong"},
		func(m *Manifest){m.DeltaSHA256="wrong"},
		func(m *Manifest){m.Blocks[0].Offset=m.SourceSize},
		func(m *Manifest){m.Blocks[0].Size=8192},
		func(m *Manifest){m.Blocks[0].DeltaOffset=4096},
		func(m *Manifest){m.Blocks[0].SHA256="wrong"},
		func(m *Manifest){m.Blocks=append(m.Blocks,m.Blocks[0])},
		func(m *Manifest){m.Blocks=nil},
	}
	for i, mutate := range oracles {
		bad := m; bad.Blocks=append([]Block(nil),m.Blocks...); mutate(&bad); write(bad)
		if q,err := Open(path); err == nil { q.Close(); t.Fatalf("oracle %d accepted",i) }
	}
	if !bytes.Equal(expect[:4096],base[:4096]) || bytes.Equal(expect,base) { t.Fatal("fixture does not distinguish dropped delta") }
}

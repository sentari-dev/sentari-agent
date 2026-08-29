package plist

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// bplistBuilder assembles a bplist00 with explicit control over the object
// bodies, offset table, and trailer so tests can craft both valid extended-count
// documents and hostile (cyclic / DAG-amplification / out-of-range) ones. It
// uses offsetSize=refSize=1, so callers must keep object indices and file
// offsets below 256 (all the crafted fixtures here are tiny).
type bplistBuilder struct {
	buf     []byte
	offsets []uint64
}

func newBplist() *bplistBuilder {
	return &bplistBuilder{buf: append([]byte{}, bplistMagic...)}
}

// add appends one object body and returns its object index.
func (b *bplistBuilder) add(body []byte) int {
	b.offsets = append(b.offsets, uint64(len(b.buf)))
	b.buf = append(b.buf, body...)
	return len(b.offsets) - 1
}

// finish appends the offset table + 32-byte trailer and returns the document.
func (b *bplistBuilder) finish(topObject int) []byte {
	offsetTableAt := uint64(len(b.buf))
	for _, off := range b.offsets {
		b.buf = append(b.buf, byte(off))
	}
	trailer := make([]byte, 32)
	trailer[6] = 1 // offsetSize
	trailer[7] = 1 // refSize
	binary.BigEndian.PutUint64(trailer[8:16], uint64(len(b.offsets)))
	binary.BigEndian.PutUint64(trailer[16:24], uint64(topObject))
	binary.BigEndian.PutUint64(trailer[24:32], offsetTableAt)
	return append(b.buf, trailer...)
}

// asciiObj builds a 1..14-byte ASCII string object body.
func asciiObj(s string) []byte {
	return append([]byte{0x50 | byte(len(s))}, []byte(s)...)
}

// intObj builds a 1-byte int object body.
func intObj(v byte) []byte { return []byte{0x10, v} }

// mustNotPanic runs Parse and fails the test if it panics; an error return is
// the CONTRACT-required outcome for malformed input, a panic is a bug.
func mustNotPanic(t *testing.T, name string, data []byte) (any, error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s: Parse PANICKED (must return an error, never panic): %v", name, r)
		}
	}()
	return Parse(data)
}

// TestParse_ExtendedCount exercises the sizedCount extended-count (lo==0xF) path
// with a >14-element array — a valid document that must decode fully.
func TestParse_ExtendedCount(t *testing.T) {
	b := newBplist()
	// 20 leaf ints, then one array of all 20 via the extended-count encoding.
	refs := make([]byte, 0, 20)
	for i := 0; i < 20; i++ {
		refs = append(refs, byte(b.add(intObj(byte(i)))))
	}
	// Array marker 0xAF (lo=0xF) + int-count marker 0x10 + count(20) + 20 refs.
	arrBody := append([]byte{0xA0 | 0x0F, 0x10, 20}, refs...)
	top := b.add(arrBody)
	doc := b.finish(top)

	v, err := mustNotPanic(t, "extended-count array", doc)
	if err != nil {
		t.Fatalf("valid extended-count array should parse: %v", err)
	}
	arr, ok := v.([]any)
	if !ok || len(arr) != 20 {
		t.Fatalf("extended-count array = %#v", v)
	}
	if arr[0] != int64(0) || arr[19] != int64(19) {
		t.Errorf("extended-count contents wrong: %v .. %v", arr[0], arr[19])
	}
}

// TestParse_CyclicRef builds a dict that references itself: the visiting set must
// break the cycle with an error, never infinite-recurse.
func TestParse_CyclicRef(t *testing.T) {
	b := newBplist()
	k := b.add(asciiObj("k")) // index 0
	// The dict is index 1 and its single value ref points back to itself (1):
	// dict marker 0xD1 + keyref(k=0) + valref(self=1).
	top := b.add([]byte{0xD0 | 1, byte(k), 1}) // index 1
	doc := b.finish(top)

	if _, err := mustNotPanic(t, "cyclic dict", doc); err == nil {
		t.Fatal("cyclic self-referential dict must error, got nil")
	}
}

// TestParse_DAGAmplificationBomb builds a small (~a few dozen bytes) non-cyclic
// DAG whose naive decode count is 14^9 (≈ 2×10^10). The decode budget must abort
// it with an error, quickly, without hanging or OOMing.
func TestParse_DAGAmplificationBomb(t *testing.T) {
	b := newBplist()
	k := byte(b.add(asciiObj("k"))) // shared key
	leaf := byte(b.add(intObj(0)))  // shared leaf

	// Build 9 dict levels bottom-up; each level has 14 entries, all key=k,
	// all value=(previous, deeper level). A plain cycle check does NOT catch
	// this because every reference is to a DISTINCT, already-fully-decoded node
	// — the amplification is in re-decoding a shared subtree 14× per level.
	child := leaf
	const width = 14
	const levels = 9
	for l := 0; l < levels; l++ {
		body := []byte{0xD0 | 0x0F, 0x10, width} // extended count = 14
		for i := 0; i < width; i++ {
			body = append(body, k) // key refs
		}
		for i := 0; i < width; i++ {
			body = append(body, child) // value refs (all the deeper level)
		}
		child = byte(b.add(body))
	}
	doc := b.finish(int(child))

	done := make(chan struct{})
	var perr error
	go func() {
		defer close(done)
		_, perr = Parse(doc)
	}()
	select {
	case <-done:
		if perr == nil {
			t.Fatal("amplification bomb must error (budget exceeded), got nil")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("amplification bomb HUNG — decode budget/depth cap not enforced")
	}
}

// TestParse_Adversarial covers a battery of malformed binary inputs. Every one
// must return an error and MUST NOT panic (the parser's "error, never panic"
// contract on untrusted admin-writable files).
func TestParse_Adversarial(t *testing.T) {
	// Valid tiny doc we then corrupt in various ways.
	base := func() *bplistBuilder {
		b := newBplist()
		b.add(asciiObj("x")) // index 0, also the top
		return b
	}

	cases := map[string][]byte{}

	// 1. Hostile numObjects in the trailer (2^61) — must be rejected up front,
	//    never used to size a make() after an overflowing multiply.
	{
		b := base()
		doc := b.finish(0)
		binary.BigEndian.PutUint64(doc[len(doc)-24:len(doc)-16], 1<<61)
		cases["hostile numObjects"] = doc
	}

	// 2. offsetTableOffset past EOF.
	{
		b := base()
		doc := b.finish(0)
		binary.BigEndian.PutUint64(doc[len(doc)-8:], uint64(len(doc))+100)
		cases["offset table past EOF"] = doc
	}

	// 3. topObject index out of range.
	{
		b := base()
		doc := b.finish(0)
		binary.BigEndian.PutUint64(doc[len(doc)-16:len(doc)-8], 99)
		cases["top object out of range"] = doc
	}

	// 4. An offset-table entry pointing beyond the object region.
	{
		b := base()
		doc := b.finish(0)
		// The single offset-table byte sits just before the trailer.
		doc[len(doc)-32-1] = 0xFF
		cases["object offset past EOF"] = doc
	}

	// 5. ASCII string with an extended count (lo==0xF) far larger than the file.
	{
		b := newBplist()
		// marker 0x5F + int-count marker 0x13 (8 bytes) + huge count.
		big := make([]byte, 8)
		binary.BigEndian.PutUint64(big, 1<<62)
		body := append([]byte{0x5F, 0x13}, big...)
		top := b.add(body)
		cases["ascii extended count overflow"] = b.finish(top)
	}

	// 6. UTF-16 string claiming 100 units (200 bytes) — far more than remain to
	//    EOF (only the offset table + trailer follow) => truncated.
	{
		b := newBplist()
		top := b.add([]byte{0x60 | 0x0F, 0x10, 100})
		cases["truncated utf16"] = b.finish(top)
	}

	// 7. Array whose element refs run past EOF.
	{
		b := newBplist()
		top := b.add([]byte{0xA0 | 0x0F, 0x10, 200}) // claims 200 refs, none present
		cases["array refs past EOF"] = b.finish(top)
	}

	// 8. Dict claiming a huge extended count.
	{
		b := newBplist()
		top := b.add([]byte{0xD0 | 0x0F, 0x10, 200})
		cases["dict refs past EOF"] = b.finish(top)
	}

	// 9. Unsupported object marker.
	{
		b := newBplist()
		top := b.add([]byte{0x70}) // 0x70 is not a type this reader implements
		cases["unsupported marker"] = b.finish(top)
	}

	// 10. Extended count whose int marker is truncated.
	{
		b := newBplist()
		top := b.add([]byte{0x5F}) // promises an extended count byte that is absent
		cases["truncated extended count"] = b.finish(top)
	}

	for name, doc := range cases {
		if _, err := mustNotPanic(t, name, doc); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}

// FuzzParse asserts Parse never panics on ANY input — the security-critical
// contract for a parser fed untrusted, admin-writable files on a root agent.
func FuzzParse(f *testing.F) {
	for _, n := range []string{"rich_bin.plist", "screensaver_bin.plist", "alf_bin.plist", "softwareupdate_bin.plist", "rich_xml.plist"} {
		if b, err := os.ReadFile(filepath.Join("testdata", n)); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte("bplist00"))
	f.Add(append([]byte("bplist00"), make([]byte, 40)...))
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Parse panicked (must never panic): %v", r)
			}
		}()
		_, _ = Parse(data) // error is acceptable; a panic or hang is not
	})
}

// Package plist is a dependency-free reader for Apple property lists, used by
// the macOS hardening collectors to read security-configuration keywords out of
// system .plist files WITHOUT invoking `defaults`/`plutil` (constraint #7) and
// WITHOUT pulling in an external module (the agent is CGO_ENABLED=0, pure-Go,
// and adds no new go.mod dependency — see the hardening PR charter).
//
// It supports the two on-disk encodings macOS uses for the files the collectors
// read:
//
//   - XML plists (`<?xml … <plist> … </plist>`), decoded with encoding/xml.
//   - Binary plists (`bplist00`), decoded by a from-scratch parser of the
//     trailer + offset table + object table.
//
// Parse returns ordinary Go values so a collector can navigate them without any
// plist-specific types:
//
//	map[string]any   ← <dict> / bplist dict
//	[]any            ← <array> / bplist array
//	string           ← <string> (ASCII or UTF-16 in binary)
//	int64            ← <integer>
//	float64          ← <real>
//	bool             ← <true/> / <false/>
//	[]byte           ← <data> / bplist data
//
// It reads only the object types the hardening keys need; an unsupported object
// marker returns an error rather than a silent wrong value (honesty over a
// fabricated PASS).
package plist

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
)

// ErrUnsupported is returned when a binary object marker is not one of the
// types this reader implements.
var ErrUnsupported = errors.New("plist: unsupported object type")

// Decode-safety limits for the binary parser. These bound work on a hostile
// admin-writable file the root agent reads: a non-cyclic DAG can re-reference a
// shared object so the naive decode count grows exponentially in the nesting
// depth (a ~1KB file → billions of decodes → OOM/CPU-hang). The `visiting` set
// only breaks true cycles; these two caps break the DAG-amplification bomb and
// runaway recursion, returning an error long before the process is harmed.
const (
	maxDecodedObjects = 100_000 // total object-decode budget across the whole tree
	maxDecodeDepth    = 64      // container-nesting recursion cap
)

// bplistMagic is the 8-byte header prefix of every binary plist.
var bplistMagic = []byte("bplist00")

// Parse decodes a property list (binary bplist00 or XML) into Go values.
// Leading whitespace / BOM before an XML document is tolerated.
func Parse(data []byte) (any, error) {
	if bytes.HasPrefix(data, bplistMagic) {
		return parseBinary(data)
	}
	trimmed := bytes.TrimLeft(data, " \t\r\n\uFEFF")
	if bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.HasPrefix(trimmed, []byte("<plist")) || bytes.HasPrefix(trimmed, []byte("<!DOCTYPE")) {
		return parseXML(trimmed)
	}
	return nil, errors.New("plist: unrecognised format (neither bplist00 nor XML)")
}

// -------------------- XML --------------------

// parseXML walks the token stream of an XML plist. It intentionally does not
// use struct unmarshalling because plist's <key>/<value> dict encoding is
// positional, not element-named.
func parseXML(data []byte) (any, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false // tolerate the DOCTYPE / entity quirks Apple emits
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if se, ok := tok.(xml.StartElement); ok {
			if se.Name.Local == "plist" {
				return xmlValue(dec)
			}
		}
	}
}

// xmlValue reads the next value element from the decoder.
func xmlValue(dec *xml.Decoder) (any, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return xmlElement(dec, t)
		case xml.EndElement:
			// </plist> with no value inside.
			return nil, nil
		}
	}
}

// xmlElement decodes a single typed element identified by its start tag.
func xmlElement(dec *xml.Decoder, start xml.StartElement) (any, error) {
	switch start.Name.Local {
	case "dict":
		return xmlDict(dec)
	case "array":
		return xmlArray(dec)
	case "true":
		return true, skipToEnd(dec, start.Name.Local)
	case "false":
		return false, skipToEnd(dec, start.Name.Local)
	case "string", "date":
		return xmlText(dec, start.Name.Local)
	case "data":
		s, err := xmlText(dec, start.Name.Local)
		if err != nil {
			return nil, err
		}
		return []byte(strings.Join(strings.Fields(s), "")), nil
	case "integer":
		s, err := xmlText(dec, start.Name.Local)
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("plist: bad integer %q: %w", s, err)
		}
		return n, nil
	case "real":
		s, err := xmlText(dec, start.Name.Local)
		if err != nil {
			return nil, err
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return nil, fmt.Errorf("plist: bad real %q: %w", s, err)
		}
		return f, nil
	default:
		return nil, fmt.Errorf("plist: unexpected element <%s>", start.Name.Local)
	}
}

// xmlText collects character data up to the matching end tag.
func xmlText(dec *xml.Decoder, name string) (string, error) {
	var sb strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb.Write(t)
		case xml.EndElement:
			if t.Name.Local == name {
				return sb.String(), nil
			}
		}
	}
}

// skipToEnd consumes tokens until the matching end tag of a self-contained
// empty element (<true/> decodes as start+end).
func skipToEnd(dec *xml.Decoder, name string) error {
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if ee, ok := tok.(xml.EndElement); ok && ee.Name.Local == name {
			return nil
		}
	}
}

// xmlDict reads <key>…</key><value/> pairs until </dict>.
func xmlDict(dec *xml.Decoder) (any, error) {
	out := make(map[string]any)
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local != "key" {
				return nil, fmt.Errorf("plist: expected <key> in <dict>, got <%s>", t.Name.Local)
			}
			key, err := xmlText(dec, "key")
			if err != nil {
				return nil, err
			}
			val, err := xmlValue(dec)
			if err != nil {
				return nil, err
			}
			out[key] = val
		case xml.EndElement:
			if t.Name.Local == "dict" {
				return out, nil
			}
		}
	}
}

// xmlArray reads value elements until </array>.
func xmlArray(dec *xml.Decoder) (any, error) {
	var out []any
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			v, err := xmlElement(dec, t)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		case xml.EndElement:
			if t.Name.Local == "array" {
				return out, nil
			}
		}
	}
}

// -------------------- binary bplist00 --------------------

// binReader holds the decoded trailer parameters for a binary plist.
type binReader struct {
	data          []byte
	offsetSize    int    // bytes per offset-table entry
	refSize       int    // bytes per object reference
	numObjects    uint64 // number of objects in the table
	offsetTableAt uint64 // file offset of the offset table
	visiting      map[uint64]bool
	decoded       uint64 // running total of object() decodes (amplification budget)
}

// parseBinary decodes a bplist00 document from its trailer inward.
func parseBinary(data []byte) (any, error) {
	if len(data) < len(bplistMagic)+32 {
		return nil, errors.New("plist: binary too short for trailer")
	}
	trailer := data[len(data)-32:]
	// Trailer layout: 5 unused, 1 sortVersion, 1 offsetIntSize, 1 objectRefSize,
	// 8 numObjects, 8 topObject, 8 offsetTableOffset (all big-endian).
	r := &binReader{
		data:          data,
		offsetSize:    int(trailer[6]),
		refSize:       int(trailer[7]),
		numObjects:    binary.BigEndian.Uint64(trailer[8:16]),
		offsetTableAt: binary.BigEndian.Uint64(trailer[24:32]),
		visiting:      make(map[uint64]bool),
	}
	topObject := binary.BigEndian.Uint64(trailer[16:24])
	if r.offsetSize < 1 || r.offsetSize > 8 || r.refSize < 1 || r.refSize > 8 {
		return nil, errors.New("plist: invalid trailer int sizes")
	}
	if r.numObjects == 0 || topObject >= r.numObjects {
		return nil, errors.New("plist: invalid object count / top object")
	}
	// A file can hold at most one object per byte; reject an absurd count up
	// front so nothing downstream multiplies a value that would wrap a uint64.
	if r.numObjects > uint64(len(data)) {
		return nil, errors.New("plist: object count exceeds file size")
	}
	// Bounds-check the offset table itself. All comparisons use subtraction /
	// division against len(data) so a crafted numObjects*offsetSize cannot wrap
	// past the bound (the classic overflow-defeats-the-check trick).
	if r.offsetTableAt < uint64(len(bplistMagic)) || r.offsetTableAt > uint64(len(data)) {
		return nil, errors.New("plist: offset table out of range")
	}
	if r.numObjects > (uint64(len(data))-r.offsetTableAt)/uint64(r.offsetSize) {
		return nil, errors.New("plist: offset table out of range")
	}
	return r.object(topObject, 0)
}

// fits reports whether the byte range [off, off+count) lies within a buffer of
// length n, computed by SUBTRACTION so off+count can never wrap the bound.
func fits(off, count uint64, n int) bool {
	ln := uint64(n)
	return off <= ln && count <= ln-off
}

// fitsN reports whether count elements of elemSize bytes each, starting at off,
// lie within a buffer of length n — computed by division so count*elemSize can
// never wrap. elemSize is always ≥1 for our callers (offset/ref sizes ≥1).
func fitsN(off, count, elemSize uint64, n int) bool {
	ln := uint64(n)
	if off > ln {
		return false
	}
	if elemSize == 0 {
		return count == 0
	}
	return count <= (ln-off)/elemSize
}

// offsetOf returns the byte offset of object #idx from the offset table.
func (r *binReader) offsetOf(idx uint64) (uint64, error) {
	if idx >= r.numObjects {
		return 0, fmt.Errorf("plist: object index %d out of range", idx)
	}
	at := r.offsetTableAt + idx*uint64(r.offsetSize)
	// Local bounds check (defence-in-depth; parseBinary already sized the whole
	// table). Subtraction form so at+offsetSize cannot wrap past len(data).
	if !fits(at, uint64(r.offsetSize), len(r.data)) {
		return 0, errors.New("plist: offset table entry out of range")
	}
	return readUint(r.data[at : at+uint64(r.offsetSize)]), nil
}

// object decodes the object at table index idx. depth is the current
// container-nesting level; it and the shared decode budget bound work on a
// hostile DAG that a plain cycle check cannot catch.
func (r *binReader) object(idx uint64, depth int) (any, error) {
	if depth > maxDecodeDepth {
		return nil, errors.New("plist: max nesting depth exceeded")
	}
	r.decoded++
	if r.decoded > maxDecodedObjects {
		return nil, errors.New("plist: object decode budget exceeded (amplification guard)")
	}
	if r.visiting[idx] {
		return nil, errors.New("plist: cyclic object reference")
	}
	off, err := r.offsetOf(idx)
	if err != nil {
		return nil, err
	}
	if off >= uint64(len(r.data)) {
		return nil, errors.New("plist: object offset out of range")
	}
	marker := r.data[off]
	hi := marker & 0xF0
	lo := marker & 0x0F

	switch hi {
	case 0x00: // singletons
		switch marker {
		case 0x00:
			return nil, nil
		case 0x08:
			return false, nil
		case 0x09:
			return true, nil
		case 0x0F:
			return nil, nil // fill byte
		default:
			return nil, fmt.Errorf("%w: marker 0x%02x", ErrUnsupported, marker)
		}
	case 0x10: // int, 2^lo bytes
		n := 1 << lo
		start := off + 1
		if !fits(start, uint64(n), len(r.data)) {
			return nil, errors.New("plist: int out of range")
		}
		return int64(readUint(r.data[start : start+uint64(n)])), nil
	case 0x20: // real, 2^lo bytes
		n := 1 << lo
		start := off + 1
		if !fits(start, uint64(n), len(r.data)) {
			return nil, errors.New("plist: real out of range")
		}
		switch n {
		case 4:
			return float64(math.Float32frombits(uint32(readUint(r.data[start : start+4])))), nil
		case 8:
			return math.Float64frombits(readUint(r.data[start : start+8])), nil
		default:
			return nil, fmt.Errorf("%w: real width %d", ErrUnsupported, n)
		}
	case 0x30: // date: 8-byte big-endian float64 (seconds since 2001)
		start := off + 1
		if !fits(start, 8, len(r.data)) {
			return nil, errors.New("plist: date out of range")
		}
		return math.Float64frombits(readUint(r.data[start : start+8])), nil
	case 0x40: // data
		count, dataOff, err := r.sizedCount(off, lo)
		if err != nil {
			return nil, err
		}
		if !fits(dataOff, count, len(r.data)) {
			return nil, errors.New("plist: data out of range")
		}
		b := make([]byte, count)
		copy(b, r.data[dataOff:dataOff+count])
		return b, nil
	case 0x50: // ASCII string
		count, dataOff, err := r.sizedCount(off, lo)
		if err != nil {
			return nil, err
		}
		if !fits(dataOff, count, len(r.data)) {
			return nil, errors.New("plist: ascii string out of range")
		}
		return string(r.data[dataOff : dataOff+count]), nil
	case 0x60: // UTF-16BE string (count is in 16-bit units)
		count, dataOff, err := r.sizedCount(off, lo)
		if err != nil {
			return nil, err
		}
		if !fitsN(dataOff, count, 2, len(r.data)) {
			return nil, errors.New("plist: utf16 string out of range")
		}
		u16 := make([]uint16, count)
		for i := uint64(0); i < count; i++ {
			u16[i] = binary.BigEndian.Uint16(r.data[dataOff+i*2 : dataOff+i*2+2])
		}
		return string(utf16.Decode(u16)), nil
	case 0xA0: // array
		count, elemOff, err := r.sizedCount(off, lo)
		if err != nil {
			return nil, err
		}
		return r.readArray(idx, count, elemOff, depth)
	case 0xD0: // dict
		count, elemOff, err := r.sizedCount(off, lo)
		if err != nil {
			return nil, err
		}
		return r.readDict(idx, count, elemOff, depth)
	default:
		return nil, fmt.Errorf("%w: marker 0x%02x", ErrUnsupported, marker)
	}
}

// sizedCount returns the element/byte count of a container or string object and
// the offset at which its payload begins. When the low nibble is 0xF the real
// count is stored as an int object immediately following the marker.
func (r *binReader) sizedCount(off uint64, lo byte) (count uint64, payloadOff uint64, err error) {
	if lo != 0x0F {
		return uint64(lo), off + 1, nil
	}
	// Extended count: next byte is an int marker (0x1n) with 2^n bytes.
	if off+1 >= uint64(len(r.data)) {
		return 0, 0, errors.New("plist: truncated extended count")
	}
	intMarker := r.data[off+1]
	if intMarker&0xF0 != 0x10 {
		return 0, 0, errors.New("plist: expected int marker for extended count")
	}
	n := uint64(1) << (intMarker & 0x0F)
	start := off + 2
	if !fits(start, n, len(r.data)) {
		return 0, 0, errors.New("plist: extended count out of range")
	}
	return readUint(r.data[start : start+n]), start + n, nil
}

// readArray resolves each element reference of an array object.
func (r *binReader) readArray(idx, count, elemOff uint64, depth int) (any, error) {
	// count*refSize checked by division so it cannot wrap the bound.
	if !fitsN(elemOff, count, uint64(r.refSize), len(r.data)) {
		return nil, errors.New("plist: array refs out of range")
	}
	r.visiting[idx] = true
	defer delete(r.visiting, idx)
	out := make([]any, count)
	for i := uint64(0); i < count; i++ {
		ref := readUint(r.data[elemOff+i*uint64(r.refSize) : elemOff+(i+1)*uint64(r.refSize)])
		v, err := r.object(ref, depth+1)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}

// readDict resolves the key-ref block then the value-ref block of a dict object.
func (r *binReader) readDict(idx, count, keyOff uint64, depth int) (any, error) {
	// The key block AND the value block are each count*refSize bytes. Check the
	// combined 2*count*refSize span by division so keyOff+count*refSize (=valOff)
	// is provably in range and cannot wrap.
	if !fitsN(keyOff, count, 2*uint64(r.refSize), len(r.data)) {
		return nil, errors.New("plist: dict refs out of range")
	}
	valOff := keyOff + count*uint64(r.refSize)
	r.visiting[idx] = true
	defer delete(r.visiting, idx)
	out := make(map[string]any, count)
	for i := uint64(0); i < count; i++ {
		kref := readUint(r.data[keyOff+i*uint64(r.refSize) : keyOff+(i+1)*uint64(r.refSize)])
		vref := readUint(r.data[valOff+i*uint64(r.refSize) : valOff+(i+1)*uint64(r.refSize)])
		kv, err := r.object(kref, depth+1)
		if err != nil {
			return nil, err
		}
		ks, ok := kv.(string)
		if !ok {
			return nil, errors.New("plist: dict key is not a string")
		}
		vv, err := r.object(vref, depth+1)
		if err != nil {
			return nil, err
		}
		out[ks] = vv
	}
	return out, nil
}

// readUint reads a big-endian unsigned integer from 1..8 bytes.
func readUint(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

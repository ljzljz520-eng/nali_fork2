package validate

import (
	"encoding/binary"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

func gbk(t *testing.T, s string) []byte {
	t.Helper()
	b, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte(s))
	if err != nil {
		t.Fatalf("gbk encode %q: %v", s, err)
	}
	return b
}

// buildQQwry builds a minimal qqwry-shaped file with two ranges:
//
//	0.0.0.0/8-ish -> record at label0
//	1.0.0.0 ...   -> record at label1
//
// Records use the default inline encoding [country 0x00][area 0x00].
func buildQQwry(t *testing.T, label0, label1 string, swapOrder bool, badOffset bool) []byte {
	t.Helper()
	buf := make([]byte, 0, 256)
	buf = append(buf, 0, 0, 0, 0, 0, 0, 0, 0) // header placeholders

	putRecord := func(label string) uint32 {
		off := uint32(len(buf))
		buf = append(buf, 0, 0, 0, 0) // 4-byte IP prefix in record area
		buf = append(buf, gbk(t, label)...)
		buf = append(buf, 0, 0) // country NUL + empty area NUL
		return off
	}
	off0 := putRecord(label0)
	off1 := putRecord(label1)

	indexStart := uint32(len(buf))
	putEntry := func(ip uint32, off uint32) {
		b := make([]byte, 7)
		binary.LittleEndian.PutUint32(b[:4], ip)
		b[4] = byte(off)
		b[5] = byte(off >> 8)
		b[6] = byte(off >> 16)
		buf = append(buf, b...)
	}
	if swapOrder {
		putEntry(1<<24, off0)
		putEntry(0, off1)
	} else {
		putEntry(0, off0)
		putEntry(1<<24, off1)
	}
	if badOffset {
		// corrupt offset of the second entry
		pos := indexStart + 7 + 4
		bad := uint32(len(buf) - 1)
		buf[pos] = byte(bad)
		buf[pos+1] = byte(bad >> 8)
		buf[pos+2] = byte(bad >> 16)
	}
	indexEnd := indexStart + 7
	binary.LittleEndian.PutUint32(buf[0:4], indexStart)
	binary.LittleEndian.PutUint32(buf[4:8], indexEnd)
	return buf
}

func permissivePolicy() Policy {
	p := DefaultPolicy()
	p.SampleSize = 200
	p.BoundarySamples = 16
	p.Thresholds.MaxAnchorMismatchRate = 1
	p.Thresholds.MaxReservedMislabelRate = 1
	return p
}

func runQQwry(t *testing.T, data, old []byte, p Policy) *Report {
	t.Helper()
	r := newReport("qqwry", FormatQQWry, "qqwry.dat", int64(len(data)), "x", "", p.EvidenceLimit)
	validateWry[uint32](r, p, data, old, wryFamilyV4())
	r.finalize()
	return r
}

func TestValidateQQwryHealthyPasses(t *testing.T) {
	data := buildQQwry(t, "IANA 保留地址", "美国 IANA保留地址", false, false)
	r := runQQwry(t, data, nil, permissivePolicy())
	if r.Quarantined() {
		t.Fatalf("expected pass, got quarantine: %+v", r.Checks)
	}
	if r.Summary["conflict_rate"] != 0 {
		t.Fatalf("conflict rate = %v", r.Summary["conflict_rate"])
	}
	if r.Summary["boundary_conflict_rate"] != 0 {
		t.Fatalf("boundary rate = %v", r.Summary["boundary_conflict_rate"])
	}
}

func TestValidateQQwryOverlappingIndexQuarantined(t *testing.T) {
	data := buildQQwry(t, "IANA 保留地址", "美国 IANA保留地址", true, false)
	r := runQQwry(t, data, nil, permissivePolicy())
	if !r.Quarantined() {
		t.Fatal("expected quarantine for unsorted index")
	}
	if !hasCheck(r, "invariants", LevelFail) {
		t.Fatal("invariants check should fail")
	}
	if !evidenceKind(r, "overlap-or-unsorted") {
		t.Fatal("missing overlap evidence")
	}
}

func TestValidateQQwryBadOffsetQuarantined(t *testing.T) {
	data := buildQQwry(t, "IANA 保留地址", "美国 IANA保留地址", false, true)
	r := runQQwry(t, data, nil, permissivePolicy())
	if !r.Quarantined() {
		t.Fatal("expected quarantine for corrupt offset")
	}
	if !hasCheck(r, "invariants", LevelFail) {
		t.Fatal("invariants check should fail")
	}
}

func TestValidateQQwryReservedMislabel(t *testing.T) {
	data := buildQQwry(t, "IANA 保留地址", "美国 加州 洛杉矶", false, false)
	p := permissivePolicy()
	p.Thresholds.MaxReservedMislabelRate = 0
	r := runQQwry(t, data, nil, p)
	if !r.Quarantined() {
		t.Fatal("expected quarantine for reserved mislabel")
	}
	if !hasCheck(r, "reserved-addresses", LevelFail) {
		t.Fatal("reserved check should fail")
	}
	if !evidenceKind(r, "reserved-mislabel") {
		t.Fatal("missing reserved-mislabel evidence")
	}
}

func TestValidateQQwryCountryJumpDiff(t *testing.T) {
	old := buildQQwry(t, "IANA 保留地址", "中国 北京 联通", false, false)
	newData := buildQQwry(t, "IANA 保留地址", "美国 纽约", false, false)
	p := permissivePolicy()
	r := runQQwry(t, newData, old, p)
	if !r.Quarantined() {
		t.Fatal("expected quarantine from country jump rate")
	}
	if !hasCheck(r, "diff-current-jump", LevelFail) {
		t.Fatal("jump check should fail")
	}
	if !evidenceKind(r, "country-jump") {
		t.Fatal("missing country-jump evidence")
	}
}

func TestValidateQQwryIdenticalNoJump(t *testing.T) {
	data := buildQQwry(t, "IANA 保留地址", "美国 IANA保留地址", false, false)
	r := runQQwry(t, data, data, permissivePolicy())
	if r.Summary["jump_rate"] != 0 {
		t.Fatalf("jump rate = %v, want 0", r.Summary["jump_rate"])
	}
}

func TestParseWryRecordModes(t *testing.T) {
	// mode2 at 20 -> country @40, area pointer @24 -> @50
	data := make([]byte, 64)
	data[20] = 0x02
	put24(data, 21, 40)
	data[24] = 0x01
	put24(data, 25, 50)
	copy(data[40:], "CN\x00")
	copy(data[50:], "area\x00")
	res, err := parseWryRecord(data, 20)
	if err != nil {
		t.Fatal(err)
	}
	if res.Country != "CN" || res.Area != "area" {
		t.Fatalf("got %q %q", res.Country, res.Area)
	}

	// mode1 redirect chain -> same record
	data[60] = 0x01
	put24(data, 61, 20)
	res2, err := parseWryRecord(data, 60)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Country != "CN" || res2.Area != "area" {
		t.Fatalf("redirect got %q %q", res2.Country, res2.Area)
	}

	// runaway redirect loop
	loop := make([]byte, 8)
	loop[0] = 0x01
	put24(loop, 1, 0)
	if _, err := parseWryRecord(loop, 0); err == nil {
		t.Fatal("expected redirect loop error")
	}

	// out of range
	if _, err := parseWryRecord([]byte{0x49}, 0); err == nil {
		t.Fatal("expected unterminated/out-of-range error")
	}
}

func put24(data []byte, pos, v uint32) {
	data[pos] = byte(v)
	data[pos+1] = byte(v >> 8)
	data[pos+2] = byte(v >> 16)
}

func hasCheck(r *Report, name string, level Level) bool {
	for _, c := range r.Checks {
		if c.Name == name && c.Level == level {
			return true
		}
	}
	return false
}

func evidenceKind(r *Report, kind string) bool {
	for _, e := range r.Evidence {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

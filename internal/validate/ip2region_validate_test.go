package validate

import (
	"encoding/binary"
	"testing"
)

type xdbRawSegment struct {
	sip, eip uint32
	region   string
}

// buildXDB assembles a minimal valid ip2region xdb buffer from segments.
// Every vector-index cell points at the whole segment region.
func buildXDB(t *testing.T, segs []xdbRawSegment) []byte {
	t.Helper()
	header := make([]byte, xdbHeaderSize)
	binary.LittleEndian.PutUint16(header[0:2], 2) // version
	binary.LittleEndian.PutUint16(header[2:4], 1) // VectorIndex policy
	binary.LittleEndian.PutUint32(header[4:8], 0) // created at
	startPtr := uint32(xdbHeaderSize + xdbVectorIndexLen)
	endPtr := startPtr + uint32(len(segs))*xdbBlockSize

	// region payload area follows the segment blocks
	regionArea := []byte{}
	segBlocks := []byte{}
	base := endPtr
	for _, s := range segs {
		dataPtr := base + uint32(len(regionArea))
		regionArea = append(regionArea, []byte(s.region)...)

		block := make([]byte, xdbBlockSize)
		binary.LittleEndian.PutUint32(block[0:4], s.sip)
		binary.LittleEndian.PutUint32(block[4:8], s.eip)
		binary.LittleEndian.PutUint16(block[8:10], uint16(len(s.region)))
		binary.LittleEndian.PutUint32(block[10:14], dataPtr)
		segBlocks = append(segBlocks, block...)
	}
	binary.LittleEndian.PutUint32(header[8:12], startPtr)
	binary.LittleEndian.PutUint32(header[12:16], endPtr)

	vector := make([]byte, xdbVectorIndexLen)
	for i := 0; i < 256*256; i++ {
		off := xdbHeaderSize + i*8
		binary.LittleEndian.PutUint32(vector[off-xdbHeaderSize:], startPtr)
		binary.LittleEndian.PutUint32(vector[off-xdbHeaderSize+4:], endPtr)
	}

	out := append(header, vector...)
	out = append(out, segBlocks...)
	out = append(out, regionArea...)
	return out
}

func TestValidateIP2RegionHealthy(t *testing.T) {
	data := buildXDB(t, []xdbRawSegment{
		{0, 0xffffffff, "中国|0|北京|北京|电信"},
	})
	p := permissivePolicy()
	r := newReport("ip2region", FormatIP2Region, "ip2region.xdb", int64(len(data)), "x", "", p.EvidenceLimit)
	validateIP2Region(r, p, data, nil)
	r.finalize()
	if r.Quarantined() {
		for _, c := range r.Checks {
			if c.Level == LevelFail {
				t.Logf("FAIL %s: %s", c.Name, c.Detail)
			}
		}
		t.Fatal("healthy xdb should pass")
	}
}

func TestValidateIP2RegionOverlap(t *testing.T) {
	data := buildXDB(t, []xdbRawSegment{
		{0, 0x01000000, "中国|0|北京|北京|电信"},
		{0x00000001, 0xffffffff, "美国|0|0|0|电信"},
	})
	p := permissivePolicy()
	r := newReport("ip2region", FormatIP2Region, "ip2region.xdb", int64(len(data)), "x", "", p.EvidenceLimit)
	validateIP2Region(r, p, data, nil)
	r.finalize()
	if !r.Quarantined() {
		t.Fatal("overlapping segments should be quarantined")
	}
	if !hasCheck(r, "invariants", LevelFail) {
		t.Fatal("invariants should fail")
	}
}

func TestValidateIP2RegionJumpDiff(t *testing.T) {
	old := buildXDB(t, []xdbRawSegment{{0, 0xffffffff, "中国|0|北京|北京|电信"}})
	newData := buildXDB(t, []xdbRawSegment{{0, 0xffffffff, "美国|0|0|0|电信"}})
	p := permissivePolicy()
	r := newReport("ip2region", FormatIP2Region, "ip2region.xdb", int64(len(newData)), "x", "", p.EvidenceLimit)
	validateIP2Region(r, p, newData, old)
	r.finalize()
	if !hasCheck(r, "diff-current-jump", LevelFail) {
		t.Fatal("country flip vs active DB should exceed jump threshold")
	}
}

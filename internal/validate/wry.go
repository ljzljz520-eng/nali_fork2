package validate

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"

	"github.com/zu1k/nali/pkg/wry"
)

// wryFamily abstracts the differences between qqwry (IPv4) and
// zxipv6wry (IPv6, top-64-bit index).
type wryFamily[T uint32 | uint64] struct {
	v6     bool
	gbk    bool
	offLen uint32
	ipLen  uint32
	// adjust is added to an index record offset before reading the mode byte.
	adjust uint32
	// parseHeader returns index start/end and record count.
	parseHeader func(data []byte) (start, end T, count T, ok bool)
	readIP      func(b []byte) T
	search      func(data []byte, start, end T, ip T) uint32
	ipString    func(ip T) string
	maxIP       T
}

func wryFamilyV4() wryFamily[uint32] {
	return wryFamily[uint32]{
		v6: false, gbk: true, offLen: 3, ipLen: 4, adjust: 4,
		parseHeader: func(data []byte) (uint32, uint32, uint32, bool) {
			if len(data) < 8 {
				return 0, 0, 0, false
			}
			s := binary.LittleEndian.Uint32(data[0:4])
			e := binary.LittleEndian.Uint32(data[4:8])
			if s >= e || uint64(e)+7 > uint64(len(data)) {
				return 0, 0, 0, false
			}
			return s, e, (e-s)/7 + 1, true
		},
		readIP: func(b []byte) uint32 { return binary.LittleEndian.Uint32(b) },
		search: func(data []byte, start, end uint32, ip uint32) uint32 {
			db := wry.IPDB[uint32]{Data: data, OffLen: 3, IPLen: 4, IdxStart: start, IdxEnd: end}
			return db.SearchIndexV4(ip)
		},
		ipString: func(ip uint32) string {
			b := []byte{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)}
			return ipStringFromBytes(b)
		},
		maxIP: ^uint32(0),
	}
}

func wryFamilyV6() wryFamily[uint64] {
	return wryFamily[uint64]{
		v6: true, gbk: false, offLen: 3, ipLen: 8, adjust: 0,
		parseHeader: func(data []byte) (uint64, uint64, uint64, bool) {
			if len(data) < 24 || string(data[:4]) != "IPDB" {
				return 0, 0, 0, false
			}
			offLen, ipLen := data[6], data[7]
			if offLen != 3 || ipLen != 8 {
				return 0, 0, 0, false
			}
			count := binary.LittleEndian.Uint64(data[8:16])
			start := binary.LittleEndian.Uint64(data[16:24])
			end := start + count*11
			if start >= end || end > uint64(len(data)) {
				return 0, 0, 0, false
			}
			return start, end, count, true
		},
		readIP: func(b []byte) uint64 { return binary.LittleEndian.Uint64(b) },
		search: func(data []byte, start, end uint64, ip uint64) uint32 {
			db := wry.IPDB[uint64]{Data: data, OffLen: 3, IPLen: 8, IdxStart: start, IdxEnd: end}
			return db.SearchIndexV6(ip)
		},
		ipString: func(ip uint64) string {
			b := make([]byte, 16)
			binary.BigEndian.PutUint64(b[:8], ip)
			return ipStringFromBytes(b)
		},
		maxIP: ^uint64(0),
	}
}

type wryEntry[T uint32 | uint64] struct {
	ip  T
	off uint32
}

func validateWry[T uint32 | uint64](r *Report, p Policy, data, oldData []byte, f wryFamily[T]) {
	start, end, count, ok := f.parseHeader(data)
	if !ok {
		r.addCheck(Check{Name: "format", Level: LevelFail, Detail: "头部或索引区间非法"})
		return
	}
	r.addCheck(Check{Name: "format", Level: LevelPass, Detail: fmt.Sprintf("%d 条索引记录", count)})

	entryLen := uint64(f.offLen + f.ipLen)
	entries := make([]wryEntry[T], 0, min64(uint64(count), 2_000_000))

	// ---- 1. structural invariants over the whole index ----
	var orderFail, parseFail uint64
	idx := func(i T) uint64 { return uint64(start) + uint64(i)*entryLen }
	for i := T(0); uint64(i) < uint64(count); i++ {
		pos := idx(i)
		if pos+entryLen > uint64(len(data)) {
			orderFail++
			r.addEvidence(Evidence{Kind: "index-out-of-range", Target: fmt.Sprintf("index#%d", i),
				Detail: fmt.Sprintf("索引位置 %d 越界", pos)})
			continue
		}
		ip := f.readIP(data[pos : pos+uint64(f.ipLen)])
		off := wry.Bytes3ToUint32(data[pos+uint64(f.ipLen) : pos+entryLen])

		if len(entries) > 0 && ip <= entries[len(entries)-1].ip {
			orderFail++
			if r.evidenceLimit > len(r.Evidence) {
				r.addEvidence(Evidence{Kind: "overlap-or-unsorted",
					Target: f.ipString(ip),
					Detail: fmt.Sprintf("索引#%d 起始地址未严格递增（重叠或乱序）", uint64(i))})
			}
		}
		if uint64(off)+uint64(f.adjust)+1 >= uint64(len(data)) {
			parseFail++
			if r.evidenceLimit > len(r.Evidence) {
				r.addEvidence(Evidence{Kind: "record-offset-out-of-range",
					Target: f.ipString(ip), Detail: fmt.Sprintf("记录偏移 %d 越界", off)})
			}
		} else if _, err := parseWryRecord(data, off+f.adjust); err != nil {
			parseFail++
			if r.evidenceLimit > len(r.Evidence) {
				r.addEvidence(Evidence{Kind: "record-parse-error",
					Target: f.ipString(ip), Actual: err.Error()})
			}
		}
		entries = append(entries, wryEntry[T]{ip: ip, off: off})
	}

	n := uint64(len(entries))
	conflictRate := float64(0)
	if n > 0 {
		conflictRate = float64(orderFail+parseFail) / float64(n)
	}
	r.Summary["conflict_rate"] = conflictRate
	r.addCheck(rateCheck("invariants", conflictRate, p.Thresholds.MaxConflictRate, true,
		fmt.Sprintf("记录数=%d 乱序/重叠=%d 解析失败=%d", n, orderFail, parseFail)))

	// ---- 2. boundary sampling ----
	rng := rand.New(rand.NewSource(p.Seed))
	boundaryIdx := sampleBoundaryIndices(n, p.BoundarySamples, rng)
	var bTested, bMismatch uint64
	for _, i := range boundaryIdx {
		cur := entries[i]
		cases := []struct {
			ip       T
			expected uint32
			desc     string
		}{
			{cur.ip, cur.off, "range-start"},
		}
		if i > 0 {
			cases = append(cases, struct {
				ip       T
				expected uint32
				desc     string
			}{cur.ip - 1, entries[i-1].off, "previous-range-end"})
		}
		if i+1 < n {
			next := entries[i+1]
			if next.ip > cur.ip {
				cases = append(cases, struct {
					ip       T
					expected uint32
					desc     string
				}{next.ip - 1, cur.off, "range-end"})
			}
		} else {
			if f.maxIP > cur.ip {
				cases = append(cases, struct {
					ip       T
					expected uint32
					desc     string
				}{f.maxIP, cur.off, "range-end"})
			}
		}
		for _, c := range cases {
			got := f.search(data, start, end, c.ip)
			bTested++
			if got != c.expected || got == 0 {
				bMismatch++
				r.addEvidence(Evidence{Kind: "boundary-mismatch",
					Target:   fmt.Sprintf("%s (%s)", f.ipString(c.ip), c.desc),
					Expected: fmt.Sprintf("offset %d", c.expected),
					Actual:   fmt.Sprintf("offset %d", got)})
			}
		}
	}
	boundaryRate := 0.0
	if bTested > 0 {
		boundaryRate = float64(bMismatch) / float64(bTested)
	}
	r.Summary["boundary_conflict_rate"] = boundaryRate
	r.addCheck(rateCheck("boundary-sampling", boundaryRate, p.Thresholds.MaxConflictRate, true,
		fmt.Sprintf("边界用例=%d 不一致=%d", bTested, bMismatch)))

	// ---- 3. random sampling + coverage ----
	randomIPs := make([]T, p.SampleSize)
	for i := range randomIPs {
		if f.v6 {
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], rng.Uint64())
			randomIPs[i] = T(binary.BigEndian.Uint64(b[:]))
		} else {
			randomIPs[i] = T(rng.Uint32())
		}
	}
	newLabels := make([]geoLabel, len(randomIPs))
	var covered int
	for i, ip := range randomIPs {
		newLabels[i] = lookupWry(data, start, end, ip, f)
		if newLabels[i].country != "" {
			covered++
		}
	}
	coverage := float64(covered) / float64(len(randomIPs))
	r.Summary["coverage"] = coverage
	cov := Check{Name: "coverage", Metrics: map[string]float64{
		"value": coverage, "threshold": p.Thresholds.MinCoverage}}
	if coverage < p.Thresholds.MinCoverage {
		cov.Level = LevelWarn
		cov.Detail = fmt.Sprintf("随机抽样非空命中率 %.2f%% 低于 %.2f%%", coverage*100, p.Thresholds.MinCoverage*100)
	} else {
		cov.Level = LevelPass
		cov.Detail = fmt.Sprintf("随机抽样非空命中率 %.2f%%", coverage*100)
	}
	r.addCheck(cov)

	// ---- 4. authoritative special-use prefixes ----
	validateWryReserved(r, p, data, start, end, f)
	// ---- 5. well-known anchors ----
	newAnchorLabels := validateWryAnchors(r, p, data, start, end, f)

	// ---- 6. diff against the active database ----
	oldStart, oldEnd, _, oldOK := f.parseHeader(oldData)
	if !oldOK {
		r.addCheck(Check{Name: "diff-current", Level: LevelPass,
			Detail: "当前库不存在或不可读，跳过与当前库的差异分析"})
		return
	}

	var compared, jumped int
	oldCovered := 0
	for i, ip := range randomIPs {
		ol := lookupWry(oldData, oldStart, oldEnd, ip, f)
		if ol.country != "" {
			oldCovered++
		}
		if ol.country != "" && newLabels[i].country != "" {
			compared++
			if ol.country != newLabels[i].country {
				jumped++
				r.addEvidence(Evidence{Kind: "country-jump",
					Target: f.ipString(ip), Previous: ol.full, Current: newLabels[i].full})
			}
		}
	}
	// anchors participate in jump detection too
	var anchors []anchor
	if f.v6 {
		anchors = anchorsV6
	} else {
		anchors = anchorsV4
	}
	for i, a := range anchors {
		ip, ok := anchorIP[T](a, f.v6)
		if !ok {
			continue
		}
		ol := lookupWry(oldData, oldStart, oldEnd, ip, f)
		nl := newAnchorLabels[i]
		if ol.country != "" && nl.country != "" && ol.country != nl.country {
			compared++
			jumped++
			r.addEvidence(Evidence{Kind: "country-jump-anchor",
				Target: a.ip, Previous: ol.full, Current: nl.full})
		}
	}

	oldCoverage := float64(oldCovered) / float64(len(randomIPs))
	jumpRate := 0.0
	if compared > 0 {
		jumpRate = float64(jumped) / float64(compared)
	}
	drop := oldCoverage - coverage
	r.Summary["jump_rate"] = jumpRate
	r.Summary["coverage_old"] = oldCoverage
	r.Summary["coverage_drop"] = drop
	r.addCheck(rateCheck("diff-current-jump", jumpRate, p.Thresholds.MaxJumpRate, true,
		fmt.Sprintf("可比样本=%d 国家/地区跳变=%d (旧库命中率 %.2f%%)", compared, jumped, oldCoverage*100)))
	r.addCheck(rateCheck("diff-current-coverage", drop, p.Thresholds.MaxCoverageDrop, true,
		fmt.Sprintf("命中率 %.2f%% -> %.2f%%", oldCoverage*100, coverage*100)))
}

type geoLabel struct {
	country string
	full    string
}

func lookupWry[T uint32 | uint64](data []byte, start, end, ip T, f wryFamily[T]) geoLabel {
	off := f.search(data, start, end, ip)
	if off == 0 || uint64(off)+uint64(f.adjust)+1 >= uint64(len(data)) {
		return geoLabel{}
	}
	res, err := parseWryRecord(data, off+f.adjust)
	if err != nil {
		return geoLabel{}
	}
	if f.gbk {
		res.DecodeGBK()
	}
	res.Trim()
	country := strings.TrimSpace(res.Country)
	full := strings.TrimSpace(country + " " + strings.TrimSpace(res.Area))
	return geoLabel{country: normalizeCountry(country), full: full}
}

func validateWryReserved[T uint32 | uint64](r *Report, p Policy, data []byte, start, end T, f wryFamily[T]) {
	var checked, mislabeled, unlabeled int
	run := func(probe, purpose string) {
		ip, ok := parseProbe[T](probe, f.v6)
		if !ok {
			return
		}
		l := lookupWry(data, start, end, ip, f)
		checked++
		switch {
		case l.full == "":
			unlabeled++
		case !labelIsReserved(l.full):
			mislabeled++
			r.addEvidence(Evidence{Kind: "reserved-mislabel", Target: probe,
				Expected: purpose, Actual: l.full})
		}
	}
	if f.v6 {
		for _, x := range reservedV6 {
			run(x.probe, x.purpose)
		}
	} else {
		for _, x := range reservedV4 {
			run(x.probe, x.purpose)
		}
	}
	rate := 0.0
	if checked > 0 {
		rate = float64(mislabeled) / float64(checked)
	}
	r.Summary["reserved_mislabel_rate"] = rate
	c := rateCheck("reserved-addresses", rate, p.Thresholds.MaxReservedMislabelRate, true,
		fmt.Sprintf("权威保留前缀=%d 误标=%d 未标注=%d", checked, mislabeled, unlabeled))
	if unlabeled > 0 && c.Level == LevelPass {
		c.Level = LevelWarn
	}
	r.addCheck(c)
}

func validateWryAnchors[T uint32 | uint64](r *Report, p Policy, data []byte, start, end T, f wryFamily[T]) []geoLabel {
	anchors := anchorsV4
	if f.v6 {
		anchors = anchorsV6
	}
	labels := make([]geoLabel, len(anchors))
	var checked, mismatched, uncovered int
	for i, a := range anchors {
		ip, ok := parseProbe[T](a.ip, f.v6)
		if !ok {
			continue
		}
		labels[i] = lookupWry(data, start, end, ip, f)
		checked++
		switch {
		case labels[i].full == "":
			uncovered++
		case !countryMatches(labels[i].full, a.tokens):
			mismatched++
			r.addEvidence(Evidence{Kind: "anchor-mismatch", Target: a.ip,
				Expected: a.country, Actual: labels[i].full})
		}
	}
	rate := 0.0
	if checked > 0 {
		rate = float64(mismatched) / float64(checked)
	}
	r.Summary["anchor_mismatch_rate"] = rate
	c := rateCheck("authoritative-anchors", rate, p.Thresholds.MaxAnchorMismatchRate, true,
		fmt.Sprintf("权威锚点=%d 不一致=%d 未覆盖=%d", checked, mismatched, uncovered))
	if uncovered > 0 && c.Level == LevelPass {
		c.Level = LevelWarn
	}
	r.addCheck(c)
	return labels
}

func sampleBoundaryIndices(n uint64, want int, rng *rand.Rand) []uint64 {
	if n == 0 {
		return nil
	}
	picked := map[uint64]struct{}{}
	add := func(i uint64) {
		if i < n {
			picked[i] = struct{}{}
		}
	}
	add(0)
	add(n - 1)
	if want < 4 {
		want = 4
	}
	stride := n / uint64(want)
	if stride == 0 {
		stride = 1
	}
	for i := uint64(0); i < n; i += stride {
		add(i)
	}
	for j := 0; j < want/4; j++ {
		add(uint64(rng.Int63n(int64(n))))
	}
	out := make([]uint64, 0, len(picked))
	for i := range picked {
		out = append(out, i)
	}
	sortUint64(out)
	return out
}

func sortUint64(s []uint64) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

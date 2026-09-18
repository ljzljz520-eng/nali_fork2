package validate

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

const (
	xdbHeaderSize     = 256
	xdbVectorIndexLen = 256 * 256 * 8
	xdbBlockSize      = 14
)

type xdbSegment struct {
	sip, eip uint32
	region   string
}

func validateIP2Region(r *Report, p Policy, data, oldData []byte) {
	if len(data) < xdbHeaderSize {
		r.addCheck(Check{Name: "format", Level: LevelFail, Detail: "文件小于 xdb 头部长度 256"})
		return
	}
	version := binary.LittleEndian.Uint16(data[0:2])
	policy := binary.LittleEndian.Uint16(data[2:4])
	startPtr := binary.LittleEndian.Uint32(data[8:12])
	endPtr := binary.LittleEndian.Uint32(data[12:16])

	if policy != 1 {
		r.addCheck(Check{Name: "format", Level: LevelFail,
			Detail: fmt.Sprintf("不支持的 xdb 索引策略 %d（仅支持 VectorIndex=1）", policy)})
		return
	}
	if startPtr < xdbHeaderSize+xdbVectorIndexLen || endPtr > uint32(len(data)) || startPtr >= endPtr {
		r.addCheck(Check{Name: "format", Level: LevelFail,
			Detail: fmt.Sprintf("段索引区间非法 [%d,%d) 文件长度=%d", startPtr, endPtr, len(data))})
		return
	}
	if (endPtr-startPtr)%xdbBlockSize != 0 {
		r.addCheck(Check{Name: "format", Level: LevelFail, Detail: "段索引长度不是 14 字节的整数倍"})
		return
	}
	r.addCheck(Check{Name: "format", Level: LevelPass,
		Detail: fmt.Sprintf("xdb 版本=%d 段数=%d", version, (endPtr-startPtr)/xdbBlockSize)})

	// ---- 1. full segment invariants (overlap/gap/region integrity) ----
	var orderFail, regionFail uint64
	var prevEip uint32
	first := true
	segments := make([]xdbSegment, 0, (endPtr-startPtr)/xdbBlockSize)
	for off := startPtr; off < endPtr; off += xdbBlockSize {
		sip := binary.LittleEndian.Uint32(data[off : off+4])
		eip := binary.LittleEndian.Uint32(data[off+4 : off+8])
		dataLen := uint32(binary.LittleEndian.Uint16(data[off+8 : off+10]))
		dataPtr := binary.LittleEndian.Uint32(data[off+10 : off+14])

		bad := sip > eip ||
			(!first && sip <= prevEip) ||
			dataPtr+dataLen > uint32(len(data))
		if bad {
			orderFail++
			r.addEvidence(Evidence{Kind: "segment-conflict",
				Target: fmt.Sprintf("%s-%s", uint32toIPStr(sip), uint32toIPStr(eip)),
				Detail: fmt.Sprintf("段重叠/乱序或区域文本越界 (ptr=%d len=%d)", dataPtr, dataLen)})
		}
		region := ""
		if dataPtr+dataLen <= uint32(len(data)) {
			region = string(data[dataPtr : dataPtr+dataLen])
			if strings.Count(region, "|") != 4 {
				regionFail++
				if r.evidenceLimit > len(r.Evidence) {
					r.addEvidence(Evidence{Kind: "region-malformed",
						Target: fmt.Sprintf("%s-%s", uint32toIPStr(sip), uint32toIPStr(eip)),
						Actual: region})
				}
			}
		}
		segments = append(segments, xdbSegment{sip: sip, eip: eip, region: region})
		prevEip = eip
		first = false
	}
	n := uint64(len(segments))
	conflictRate := 0.0
	if n > 0 {
		conflictRate = float64(orderFail+regionFail) / float64(n)
	}
	r.Summary["conflict_rate"] = conflictRate
	r.addCheck(rateCheck("invariants", conflictRate, p.Thresholds.MaxConflictRate, true,
		fmt.Sprintf("段数=%d 重叠/乱序=%d 文本异常=%d", n, orderFail, regionFail)))

	searcher, err := xdb.NewWithBuffer(data)
	if err != nil {
		r.addCheck(Check{Name: "format", Level: LevelFail, Detail: "无法加载 xdb: " + err.Error()})
		return
	}

	// ---- 2. boundary sampling: sip/eip must resolve to the segment ----
	rng := rand.New(rand.NewSource(p.Seed))
	var bTested, bMismatch uint64
	pickCount := p.BoundarySamples
	if uint64(pickCount) > n {
		pickCount = int(n)
	}
	for i := 0; i < pickCount; i++ {
		seg := segments[uint64(rng.Int63n(int64(n)))]
		for _, ip := range []uint32{seg.sip, seg.eip} {
			got, err := searcher.Search(ip)
			bTested++
			if err != nil || got != seg.region {
				bMismatch++
				r.addEvidence(Evidence{Kind: "boundary-mismatch",
					Target:   uint32toIPStr(ip),
					Expected: seg.region,
					Actual:   fmt.Sprintf("%v (err=%v)", got, err)})
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
	lookup := func(s *xdb.Searcher, ip uint32) geoLabel { return xdbLabelSafe(s, ip) }
	randomIPs := make([]uint32, p.SampleSize)
	for i := range randomIPs {
		randomIPs[i] = rng.Uint32()
	}
	newLabels := make([]geoLabel, len(randomIPs))
	covered := 0
	for i, ip := range randomIPs {
		newLabels[i] = lookup(searcher, ip)
		if newLabels[i].country != "" {
			covered++
		}
	}
	coverage := float64(covered) / float64(len(randomIPs))
	r.Summary["coverage"] = coverage
	c := Check{Name: "coverage", Metrics: map[string]float64{"value": coverage, "threshold": p.Thresholds.MinCoverage}}
	if coverage < p.Thresholds.MinCoverage {
		c.Level = LevelWarn
	} else {
		c.Level = LevelPass
	}
	c.Detail = fmt.Sprintf("随机抽样非空命中率 %.2f%%", coverage*100)
	r.addCheck(c)

	// ---- 4/5. reserved prefixes + anchors ----
	var checked, mislabeled, unlabeled int
	for _, x := range reservedV4 {
		ip, ok := parseProbe[uint32](x.probe, false)
		if !ok {
			continue
		}
		l := lookup(searcher, ip)
		checked++
		switch {
		case l.full == "":
			unlabeled++
		case !labelIsReserved(l.full):
			mislabeled++
			r.addEvidence(Evidence{Kind: "reserved-mislabel", Target: x.probe, Expected: x.purpose, Actual: l.full})
		}
	}
	reservedRate := 0.0
	if checked > 0 {
		reservedRate = float64(mislabeled) / float64(checked)
	}
	r.Summary["reserved_mislabel_rate"] = reservedRate
	rc := rateCheck("reserved-addresses", reservedRate, p.Thresholds.MaxReservedMislabelRate, true,
		fmt.Sprintf("权威保留前缀=%d 误标=%d 未标注=%d", checked, mislabeled, unlabeled))
	if unlabeled > 0 && rc.Level == LevelPass {
		rc.Level = LevelWarn
	}
	r.addCheck(rc)

	var aChecked, aMismatch, aUncovered int
	for _, a := range anchorsV4 {
		ip, ok := parseProbe[uint32](a.ip, false)
		if !ok {
			continue
		}
		l := lookup(searcher, ip)
		aChecked++
		switch {
		case l.full == "":
			aUncovered++
		case !countryMatches(l.full, a.tokens):
			aMismatch++
			r.addEvidence(Evidence{Kind: "anchor-mismatch", Target: a.ip, Expected: a.country, Actual: l.full})
		}
	}
	anchorRate := 0.0
	if aChecked > 0 {
		anchorRate = float64(aMismatch) / float64(aChecked)
	}
	r.Summary["anchor_mismatch_rate"] = anchorRate
	ac := rateCheck("authoritative-anchors", anchorRate, p.Thresholds.MaxAnchorMismatchRate, true,
		fmt.Sprintf("权威锚点=%d 不一致=%d 未覆盖=%d", aChecked, aMismatch, aUncovered))
	if aUncovered > 0 && ac.Level == LevelPass {
		ac.Level = LevelWarn
	}
	r.addCheck(ac)

	// ---- 6. diff against active xdb ----
	oldSearcher, err := xdb.NewWithBuffer(oldData)
	if err != nil || len(oldData) < xdbHeaderSize {
		r.addCheck(Check{Name: "diff-current", Level: LevelPass,
			Detail: "当前库不存在或不可读，跳过与当前库的差异分析"})
		return
	}
	oldCovered, compared, jumped := 0, 0, 0
	for i, ip := range randomIPs {
		ol := lookup(oldSearcher, ip)
		if ol.country != "" {
			oldCovered++
		}
		if ol.country != "" && newLabels[i].country != "" {
			compared++
			if ol.country != newLabels[i].country {
				jumped++
				r.addEvidence(Evidence{Kind: "country-jump", Target: uint32toIPStr(ip),
					Previous: ol.full, Current: newLabels[i].full})
			}
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

func xdbLabelSafe(s *xdb.Searcher, ip uint32) geoLabel {
	region, err := s.Search(ip)
	if err != nil || region == "" {
		return geoLabel{}
	}
	fields := strings.Split(region, "|")
	country := ""
	if len(fields) > 0 && fields[0] != "0" {
		country = fields[0]
	}
	clean := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "0" && f != "" {
			clean = append(clean, f)
		}
	}
	return geoLabel{country: normalizeCountry(country), full: strings.Join(clean, " ")}
}

func uint32toIPStr(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

package validate

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/zu1k/nali/pkg/re"
	"gopkg.in/yaml.v2"
)

type cdnEntry struct {
	Name string `yaml:"name"`
	Link string `yaml:"link"`
}

func validateCDN(r *Report, p Policy, data, oldData []byte) {
	entries := map[string]cdnEntry{}
	if err := yaml.Unmarshal(data, &entries); err != nil {
		r.addCheck(Check{Name: "format", Level: LevelFail, Detail: "YAML 解析失败: " + err.Error()})
		return
	}
	r.addCheck(Check{Name: "format", Level: LevelPass, Detail: fmt.Sprintf("CDN 条目=%d", len(entries))})

	var domainCount, regexCount, emptyName int
	invalidKeys := []string{}

	type regexStat struct {
		pattern    string
		score      int
		dangerous  []string
		maxMatchUS int64
	}
	var stats []regexStat

	// adversarial inputs used to surface pathological match costs.
	adversarial := []string{
		strings.Repeat("a", 256),
		strings.Repeat("a", 256) + ".com",
		strings.Repeat("a.", 128) + "com",
		strings.Repeat("a-", 128) + "com",
		"x" + strings.Repeat("a", 255) + ".example.com",
		strings.Repeat("a", 64) + "." + strings.Repeat("b", 64) + "." + strings.Repeat("c", 64) + ".com",
		strings.Repeat("0", 256),
		strings.Repeat("-", 256),
	}

	for k, v := range entries {
		if strings.TrimSpace(v.Name) == "" {
			emptyName++
			r.addEvidence(Evidence{Kind: "cdn-empty-name", Target: k})
		}
		if !re.MaybeRegexp(k) {
			domainCount++
			if !looksLikeDomain(k) {
				r.addEvidence(Evidence{Kind: "cdn-invalid-domain", Target: k,
					Detail: "普通键不是合法域名（如确为正则需包含 . * + ? ( ) [ ] 等元字符）"})
			}
			continue
		}
		regexCount++
		rex, err := regexp.Compile(k)
		stat := regexStat{pattern: k, score: regexScore(k)}
		if err != nil {
			invalidKeys = append(invalidKeys, k)
			r.addEvidence(Evidence{Kind: "cdn-invalid-regex", Target: k, Actual: err.Error()})
			stats = append(stats, stat)
			continue
		}
		stat.dangerous = regexDanger(k)
		for _, in := range adversarial {
			d := timedMatch(rex, in)
			if d > stat.maxMatchUS {
				stat.maxMatchUS = d
			}
		}
		if len(stat.dangerous) > 0 {
			r.addEvidence(Evidence{Kind: "cdn-regex-dangerous-shape", Target: k,
				Detail: strings.Join(stat.dangerous, "; ")})
		}
		if stat.score > p.Thresholds.MaxRegexComplexity {
			r.addEvidence(Evidence{Kind: "cdn-regex-too-complex", Target: k,
				Actual: fmt.Sprintf("复杂度 %d > 阈值 %d", stat.score, p.Thresholds.MaxRegexComplexity)})
		}
		if time.Duration(stat.maxMatchUS)*time.Microsecond >
			time.Duration(p.Thresholds.MaxRegexMatchMS*float64(time.Millisecond)) {
			r.addEvidence(Evidence{Kind: "cdn-regex-slow-match", Target: k,
				Actual: fmt.Sprintf("对抗输入最长匹配 %.2fms", float64(stat.maxMatchUS)/1000)})
		}
		stats = append(stats, stat)
	}

	r.Summary["entry_count"] = float64(len(entries))
	r.Summary["regex_count"] = float64(regexCount)

	// invalid regexes are a hard corruption signal.
	c := rateCountCheck("regex-compile", len(invalidKeys), p.Thresholds.MaxInvalidRegex,
		fmt.Sprintf("正则条目=%d 编译失败=%d", regexCount, len(invalidKeys)))
	r.addCheck(c)

	dangerShape := 0
	overComplex := 0
	slow := 0
	maxUS := int64(0)
	for _, s := range stats {
		if len(s.dangerous) > 0 {
			dangerShape++
		}
		if s.score > p.Thresholds.MaxRegexComplexity {
			overComplex++
		}
		if s.maxMatchUS > maxUS {
			maxUS = s.maxMatchUS
		}
		if time.Duration(s.maxMatchUS)*time.Microsecond >
			time.Duration(p.Thresholds.MaxRegexMatchMS*float64(time.Millisecond)) {
			slow++
		}
	}
	r.Summary["regex_max_match_ms"] = float64(maxUS) / 1000
	r.Summary["regex_dangerous_count"] = float64(dangerShape)

	dc := Check{Name: "regex-complexity", Metrics: map[string]float64{
		"dangerous_shapes": float64(dangerShape),
		"over_complex":     float64(overComplex),
		"slow_matches":     float64(slow),
		"worst_ms":         float64(maxUS) / 1000,
	}}
	if (p.Thresholds.ForbidDangerousRegex && dangerShape > 0) || overComplex > 0 || slow > 0 {
		dc.Level = LevelFail
		dc.Detail = fmt.Sprintf("灾难性回溯形状=%d 复杂度过高=%d 慢匹配=%d 最慢 %.2fms",
			dangerShape, overComplex, slow, float64(maxUS)/1000)
	} else {
		dc.Level = LevelPass
		dc.Detail = fmt.Sprintf("正则=%d 最慢匹配 %.3fms，无危险形状", regexCount, float64(maxUS)/1000)
	}
	r.addCheck(dc)

	ec := Check{Name: "entry-integrity"}
	ec.Metrics = map[string]float64{"empty_name": float64(emptyName), "entries": float64(len(entries))}
	if emptyName > 0 || len(entries) == 0 {
		ec.Level = LevelFail
	} else {
		ec.Level = LevelPass
	}
	ec.Detail = fmt.Sprintf("域名条目=%d 正则条目=%d 空名称=%d", domainCount, regexCount, emptyName)
	r.addCheck(ec)

	// ---- diff against the active cdn.yml ----
	old := map[string]cdnEntry{}
	if err := yaml.Unmarshal(oldData, &old); err != nil || len(old) == 0 {
		r.addCheck(Check{Name: "diff-current", Level: LevelPass,
			Detail: "当前库不存在或不可读，跳过与当前库的差异分析"})
		return
	}
	added, removed, changed := 0, 0, 0
	for k, v := range entries {
		ov, ok := old[k]
		switch {
		case !ok:
			added++
		case ov.Name != v.Name || ov.Link != v.Link:
			changed++
			r.addEvidence(Evidence{Kind: "cdn-entry-changed", Target: k, Previous: ov.Name, Current: v.Name})
		}
	}
	for k := range old {
		if _, ok := entries[k]; !ok {
			removed++
			r.addEvidence(Evidence{Kind: "cdn-entry-removed", Target: k, Previous: old[k].Name})
		}
	}
	changeRate := float64(removed+changed) / float64(len(old))
	r.Summary["change_rate"] = changeRate
	r.addCheck(rateCheck("diff-current", changeRate, p.Thresholds.MaxCDNChangeRate, true,
		fmt.Sprintf("旧条目=%d 新增=%d 删除=%d 修改=%d", len(old), added, removed, changed)))
}

func rateCountCheck(name string, value, threshold int, detail string) Check {
	c := Check{Name: name, Detail: detail,
		Metrics: map[string]float64{"value": float64(value), "threshold": float64(threshold)}}
	if value > threshold {
		c.Level = LevelFail
	} else {
		c.Level = LevelPass
	}
	return c
}

// looksLikeDomain performs a lightweight static check of plain CDN keys.
func looksLikeDomain(s string) bool {
	// Accept the absolute/FQDN root-label form ("example.com.").
	s = strings.TrimSuffix(s, ".")
	if len(s) == 0 || len(s) > 253 || strings.ContainsAny(s, " \t\r\n/") {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
				c >= '0' && c <= '9' || c == '-' || c == '*') {
				return false
			}
		}
	}
	return true
}

func timedMatch(rex *regexp.Regexp, input string) (maxUS int64) {
	defer func() { _ = recover() }()
	start := time.Now()
	_ = rex.MatchString(input)
	return time.Since(start).Microseconds()
}

// regexScore is a static complexity score: length, grouping, repetition,
// alternation and nesting depth.
func regexScore(pattern string) int {
	score := len(pattern)
	depth, maxDepth := 0, 0
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '\\':
			i++ // skip escaped char
		case '(':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
			score += 3
		case ')':
			if depth > 0 {
				depth--
			}
		case '*', '+', '?':
			score += 2
		case '{':
			score += 2
		case '|':
			score++
		case '[':
			score++
		}
	}
	score += maxDepth * 5
	return score
}

// regexDanger statically detects shapes associated with catastrophic
// backtracking: a quantified group whose own body contains repetition or
// overlapping alternatives. Returns human-readable reasons.
func regexDanger(pattern string) []string {
	type node struct {
		start      int
		bodyHasQ   bool // body directly contains a quantifier
		bodyHasAlt bool // body directly contains an alternation
		repeatNext bool // token after ')' is a quantifier
	}
	var groups []node
	stack := []int{}
	escaped := false
	classDepth := 0
	bodyQ := map[int]bool{}
	bodyAlt := map[int]bool{}

	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '[' {
			classDepth++
			continue
		}
		if c == ']' {
			if classDepth > 0 {
				classDepth--
			}
			continue
		}
		if classDepth > 0 {
			continue
		}
		switch c {
		case '(':
			idx := len(groups)
			groups = append(groups, node{start: i})
			stack = append(stack, idx)
		case ')':
			if len(stack) == 0 {
				continue
			}
			idx := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			groups[idx].bodyHasQ = bodyQ[idx]
			groups[idx].bodyHasAlt = bodyAlt[idx]
			// look ahead past ')' for a quantifier
			j := i + 1
			if j < len(pattern) {
				switch pattern[j] {
				case '+', '*', '?':
					groups[idx].repeatNext = true
				case '{':
					if k := strings.IndexByte(pattern[j:], '}'); k > 0 {
						groups[idx].repeatNext = true
					}
				}
			}
		case '+', '*', '?':
			if len(stack) > 0 {
				bodyQ[stack[len(stack)-1]] = true
			}
		case '{':
			if len(stack) > 0 {
				bodyQ[stack[len(stack)-1]] = true
			}
		case '|':
			if len(stack) > 0 {
				bodyAlt[stack[len(stack)-1]] = true
			}
		}
	}

	var reasons []string
	for _, g := range groups {
		if !g.repeatNext {
			continue
		}
		if g.bodyHasQ {
			reasons = append(reasons, fmt.Sprintf("位置 %d: 被量词修饰的分组内部仍含量词（如 (a+)+ 形状）", g.start))
		}
		if g.bodyHasAlt {
			reasons = append(reasons, fmt.Sprintf("位置 %d: 被量词修饰的分组内含分支（如 (a|ab)+ 形状，分支可能重叠）", g.start))
		}
	}
	return reasons
}

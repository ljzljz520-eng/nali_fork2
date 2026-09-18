package validate

import "github.com/spf13/viper"

// Policy controls how a freshly downloaded database is validated before it
// is allowed to replace the active database.
type Policy struct {
	Enabled bool

	// SampleSize is the number of deterministic random IPs queried per DB.
	SampleSize int
	// BoundarySamples limits the number of index boundaries exercised.
	BoundarySamples int
	// Seed makes the random sampling reproducible across update runs.
	Seed int64
	// EvidenceLimit caps the number of evidence entries kept per report.
	EvidenceLimit int

	Thresholds Thresholds
}

// Thresholds are the policy limits. Exceeding a fail-threshold quarantines
// the database.
type Thresholds struct {
	// MaxConflictRate: fraction of records that violate structural
	// invariants (unsorted / overlapping index, unparsable records,
	// boundary lookup inconsistency).
	MaxConflictRate float64
	// MaxJumpRate: fraction of sampled IPs whose country label changes
	// against the currently active database.
	MaxJumpRate float64
	// MaxCoverageDrop: allowed absolute drop of the non-empty answer rate
	// against the currently active database.
	MaxCoverageDrop float64
	// MaxReservedMislabelRate: fraction of authoritative special-use
	// prefixes (RFC 6890 / RFC 4291) carrying a geographic label.
	MaxReservedMislabelRate float64
	// MaxAnchorMismatchRate: fraction of well-known anycast anchors
	// (Google/AliDNS/...) whose label contradicts the expected country.
	MaxAnchorMismatchRate float64
	// MinCoverage: absolute lower bound of the non-empty answer rate.
	MinCoverage float64

	// MaxInvalidRegex: number of CDN patterns that fail to compile.
	MaxInvalidRegex int
	// MaxRegexComplexity: static complexity score per CDN pattern.
	MaxRegexComplexity int
	// ForbidDangerousRegex rejects patterns with nested/repeated
	// quantifiers (catastrophic-backtracking shape) outright.
	ForbidDangerousRegex bool
	// MaxRegexMatchMS: worst-case match time against adversarial inputs.
	MaxRegexMatchMS float64
	// MaxCDNChangeRate: fraction of CDN entries removed/changed vs active.
	MaxCDNChangeRate float64
}

// DefaultPolicy returns conservative, production-friendly defaults.
func DefaultPolicy() Policy {
	return Policy{
		Enabled:         true,
		SampleSize:      1000,
		BoundarySamples: 256,
		Seed:            20240520,
		EvidenceLimit:   50,
		Thresholds: Thresholds{
			MaxConflictRate:         0.0,
			MaxJumpRate:             0.05,
			MaxCoverageDrop:         0.05,
			MaxReservedMislabelRate: 0.25,
			MaxAnchorMismatchRate:   0.5,
			MinCoverage:             0.5,

			MaxInvalidRegex:      0,
			MaxRegexComplexity:   200,
			ForbidDangerousRegex: true,
			MaxRegexMatchMS:      50,
			MaxCDNChangeRate:     0.5,
		},
	}
}

// LoadPolicy reads the policy from viper, falling back to defaults.
func LoadPolicy() Policy {
	p := DefaultPolicy()
	if v := viper.Get("validate"); v == nil {
		return p
	}

	g := func(key string, def float64) float64 {
		if viper.IsSet("validate." + key) {
			return viper.GetFloat64("validate." + key)
		}
		return def
	}
	gi := func(key string, def int) int {
		if viper.IsSet("validate." + key) {
			return viper.GetInt("validate." + key)
		}
		return def
	}
	gb := func(key string, def bool) bool {
		if viper.IsSet("validate." + key) {
			return viper.GetBool("validate." + key)
		}
		return def
	}
	gt := func(key string, def float64) float64 {
		return g("thresholds."+key, def)
	}

	p.Enabled = gb("enabled", p.Enabled)
	p.SampleSize = gi("sample-size", p.SampleSize)
	p.BoundarySamples = gi("boundary-samples", p.BoundarySamples)
	p.Seed = int64(gi("seed", int(p.Seed)))
	p.EvidenceLimit = gi("evidence-limit", p.EvidenceLimit)

	t := &p.Thresholds
	t.MaxConflictRate = gt("max-conflict-rate", t.MaxConflictRate)
	t.MaxJumpRate = gt("max-jump-rate", t.MaxJumpRate)
	t.MaxCoverageDrop = gt("max-coverage-drop", t.MaxCoverageDrop)
	t.MaxReservedMislabelRate = gt("max-reserved-mislabel-rate", t.MaxReservedMislabelRate)
	t.MaxAnchorMismatchRate = gt("max-anchor-mismatch-rate", t.MaxAnchorMismatchRate)
	t.MinCoverage = gt("min-coverage", t.MinCoverage)
	t.MaxInvalidRegex = gi("thresholds.max-invalid-regex", t.MaxInvalidRegex)
	t.MaxRegexComplexity = gi("thresholds.max-regex-complexity", t.MaxRegexComplexity)
	t.ForbidDangerousRegex = gb("thresholds.forbid-dangerous-regex", t.ForbidDangerousRegex)
	t.MaxRegexMatchMS = gt("max-regex-match-ms", t.MaxRegexMatchMS)
	t.MaxCDNChangeRate = gt("max-cdn-change-rate", t.MaxCDNChangeRate)
	return p
}

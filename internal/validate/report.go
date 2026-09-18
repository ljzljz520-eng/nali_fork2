package validate

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

// Level is the outcome of a single check.
type Level string

const (
	LevelPass Level = "pass"
	LevelWarn Level = "warn"
	LevelFail Level = "fail"
)

// Verdict describes whether the candidate database may replace the active one.
type Verdict string

const (
	// VerdictPass: all checks within policy, the DB can be activated.
	VerdictPass Verdict = "pass"
	// VerdictQuarantine: at least one hard threshold was exceeded.
	VerdictQuarantine Verdict = "quarantine"
)

// Check is one named validation outcome.
type Check struct {
	Name    string             `json:"name"`
	Level   Level              `json:"level"`
	Detail  string             `json:"detail,omitempty"`
	Metrics map[string]float64 `json:"metrics,omitempty"`
}

// Evidence is a single sampled fact a human can inspect.
type Evidence struct {
	Kind     string `json:"kind"`
	Target   string `json:"target"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Previous string `json:"previous,omitempty"`
	Current  string `json:"current,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// Report is the full validation artifact persisted alongside quarantined DBs.
type Report struct {
	DBName       string `json:"db_name"`
	Format       string `json:"format"`
	File         string `json:"file"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
	ActiveSHA256 string `json:"active_sha256,omitempty"`
	GeneratedAt  string `json:"generated_at"`

	Verdict  Verdict            `json:"verdict"`
	Summary  map[string]float64 `json:"summary,omitempty"`
	Checks   []Check            `json:"checks"`
	Evidence []Evidence         `json:"evidence,omitempty"`

	evidenceLimit int
}

func newReport(name, format, file string, size int64, sum, activeSum string, evidenceLimit int) *Report {
	return &Report{
		DBName:        name,
		Format:        format,
		File:          file,
		Size:          size,
		SHA256:        sum,
		ActiveSHA256:  activeSum,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Verdict:       VerdictPass,
		Summary:       map[string]float64{},
		Checks:        []Check{},
		Evidence:      []Evidence{},
		evidenceLimit: evidenceLimit,
	}
}

func (r *Report) addEvidence(e Evidence) {
	if len(r.Evidence) >= r.evidenceLimit {
		return
	}
	r.Evidence = append(r.Evidence, e)
}

func (r *Report) addCheck(c Check) {
	if c.Metrics == nil {
		c.Metrics = map[string]float64{}
	}
	r.Checks = append(r.Checks, c)
	if c.Level == LevelFail {
		r.Verdict = VerdictQuarantine
	}
}

// Quarantined reports whether the report exceeds the policy.
func (r *Report) Quarantined() bool {
	return r.Verdict == VerdictQuarantine
}

func (r *Report) finalize() {
	if r.Verdict == "" {
		r.Verdict = VerdictPass
	}
	// Keep the JSON artifacts stable.
	sort.SliceStable(r.Checks, func(i, j int) bool { return r.Checks[i].Name < r.Checks[j].Name })
}

func (r *Report) writeJSON(path string) error {
	r.finalize()
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadReport reads a report.json produced during quarantine.
func LoadReport(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r := &Report{}
	if err := json.Unmarshal(data, r); err != nil {
		return nil, fmt.Errorf("parse report %s: %w", path, err)
	}
	return r, nil
}

// rateCheck builds a fail/warn check by comparing a rate against a threshold.
func rateCheck(name string, value, threshold float64, fail bool, detail string) Check {
	level := LevelPass
	if value > threshold+1e-12 {
		if fail {
			level = LevelFail
		} else {
			level = LevelWarn
		}
	}
	return Check{
		Name:   name,
		Level:  level,
		Detail: detail,
		Metrics: map[string]float64{
			"value":     value,
			"threshold": threshold,
		},
	}
}

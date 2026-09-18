package validate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zu1k/nali/internal/constant"
)

const (
	quarantineRoot = "quarantine"
	reportFileName = "report.json"
)

// Entry describes one quarantined database snapshot.
type Entry struct {
	DBName    string
	ID        string
	Dir       string
	Payload   string
	Report    *Report
	ReportErr error
}

// Store persists a rejected candidate database together with its report.
// Returns the quarantine directory.
func Store(r *Report, data []byte) (string, error) {
	id := time.Now().Format("20060102-150405")
	dir := filepath.Join(RootDir(), r.DBName, id)
	if _, err := os.Stat(dir); err == nil {
		id = id + "-" + randomSuffix()
		dir = filepath.Join(RootDir(), r.DBName, id)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}

	payloadName := filepath.Base(r.File)
	if payloadName == "." || payloadName == "/" || payloadName == "" {
		payloadName = r.DBName + ".db"
	}
	payloadPath := filepath.Join(dir, payloadName)
	tmp := payloadPath + ".part"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, payloadPath); err != nil {
		return "", err
	}
	if err := r.writeJSON(filepath.Join(dir, reportFileName)); err != nil {
		return "", err
	}
	return dir, nil
}

// StoreUnexpected persists a candidate that could not even be validated
// (e.g. validator crashed). It is conservative: untrusted bytes never
// overwrite the active database.
func StoreUnexpected(dbName, format, activePath string, data []byte, cause error) (string, error) {
	r := newReport(dbName, format, activePath, int64(len(data)), sha256sum(data), "", 0)
	r.addCheck(Check{Name: "validator", Level: LevelFail, Detail: "校验过程异常: " + cause.Error()})
	r.finalize()
	return Store(r, data)
}

// rootDirOverride overrides the on-disk quarantine root (tests only).
var rootDirOverride string

// RootDir is the quarantine directory under the nali data home.
func RootDir() string {
	if rootDirOverride != "" {
		return filepath.Join(rootDirOverride, quarantineRoot)
	}
	return filepath.Join(constant.DataDirPath, quarantineRoot)
}

// List returns all quarantined snapshots, newest entry first within each DB.
func List() (map[string][]Entry, error) {
	out := map[string][]Entry{}
	root := RootDir()
	groups, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	for _, g := range groups {
		if !g.IsDir() {
			continue
		}
		dbName := g.Name()
		snapshots, err := os.ReadDir(filepath.Join(root, dbName))
		if err != nil {
			continue
		}
		var entries []Entry
		for _, s := range snapshots {
			if !s.IsDir() {
				continue
			}
			id := s.Name()
			dir := filepath.Join(root, dbName, id)
			e := Entry{DBName: dbName, ID: id, Dir: dir}
			e.Payload = findPayload(dir, reportFileName)
			if repPath := filepath.Join(dir, reportFileName); fileExists(repPath) {
				e.Report, e.ReportErr = LoadReport(repPath)
			}
			entries = append(entries, e)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].ID > entries[j].ID })
		if len(entries) > 0 {
			out[dbName] = entries
		}
	}
	return out, nil
}

// LatestEntry returns the newest snapshot for a database.
func LatestEntry(dbName string) (*Entry, error) {
	all, err := List()
	if err != nil {
		return nil, err
	}
	entries, ok := all[dbName]
	if !ok || len(entries) == 0 {
		return nil, fmt.Errorf("数据库 %s 没有隔离中的版本", dbName)
	}
	return &entries[0], nil
}

// GetEntry returns one snapshot by id, or the latest when id is empty.
func GetEntry(dbName, id string) (*Entry, error) {
	if strings.TrimSpace(id) == "" {
		return LatestEntry(dbName)
	}
	dir := filepath.Join(RootDir(), dbName, id)
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("隔离版本 %s/%s 不存在", dbName, id)
	}
	e := &Entry{DBName: dbName, ID: id, Dir: dir}
	e.Payload = findPayload(dir, reportFileName)
	if fileExists(filepath.Join(dir, reportFileName)) {
		e.Report, e.ReportErr = LoadReport(filepath.Join(dir, reportFileName))
	}
	return e, nil
}

// Activate moves an inspected snapshot into the active database location.
// The checksum is verified against the stored report before the swap.
func Activate(e *Entry, targetPath string) error {
	if e.Payload == "" {
		return errors.New("隔离目录中找不到数据库文件")
	}
	data, err := os.ReadFile(e.Payload)
	if err != nil {
		return fmt.Errorf("读取隔离文件失败: %w", err)
	}
	if e.Report != nil {
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if got != e.Report.SHA256 {
			return fmt.Errorf("校验和不一致（报告 %s，实际 %s），拒绝激活", e.Report.SHA256[:12], got[:12])
		}
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return err
	}
	if err := moveFile(e.Payload, targetPath); err != nil {
		return err
	}
	// Keep the evidence around; remove only the (now empty) snapshot dir
	// if nothing but the report remains.
	_ = os.Remove(filepath.Join(e.Dir, reportFileName))
	entries, _ := os.ReadDir(e.Dir)
	if len(entries) == 0 {
		_ = os.Remove(e.Dir)
	}
	return nil
}

func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	// Cross-filesystem fallback: copy then remove.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst+".part", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Rename(dst+".part", dst); err != nil {
		return err
	}
	return os.Remove(src)
}

func findPayload(dir string, excludes ...string) string {
	files, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		skip := false
		for _, ex := range excludes {
			if f.Name() == ex || strings.HasSuffix(f.Name(), ".part") {
				skip = true
			}
		}
		if !skip {
			return filepath.Join(dir, f.Name())
		}
	}
	return ""
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func randomSuffix() string {
	return fmt.Sprintf("%03d", time.Now().Nanosecond()/1e6)
}

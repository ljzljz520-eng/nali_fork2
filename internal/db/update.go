package db

import (
	"errors"
	"log"
	"strings"
	"time"

	"github.com/zu1k/nali/internal/validate"
	"github.com/zu1k/nali/pkg/common"
	"github.com/zu1k/nali/pkg/download"
	"github.com/zu1k/nali/pkg/qqwry"
	"github.com/zu1k/nali/pkg/zxipv6wry"
)

func UpdateDB(dbNames ...string) {
	if len(dbNames) == 0 {
		dbNames = DbNameListForUpdate
	}

	done := make(map[string]struct{})
	for _, dbName := range dbNames {
		update, name := getUpdateFuncByName(dbName)
		if _, found := done[name]; !found {
			done[name] = struct{}{}
			_ = update()
		}
	}
}

var DbNameListForUpdate = []string{
	"qqwry",
	"zxipv6wry",
	"ip2region",
	"cdn",
}

var DbCheckFunc = map[Format]func([]byte) bool{
	FormatQQWry:     qqwry.CheckFile,
	FormatZXIPv6Wry: zxipv6wry.CheckFile,
}

// admitDownload runs the legacy structural format check and the content
// validation pipeline. A passing database replaces the active file; a
// rejected one is quarantined and the active file stays untouched.
func admitDownload(dbInfo *DB, data []byte) error {
	if check, ok := DbCheckFunc[dbInfo.Format]; ok && !check(data) {
		log.Printf("%s 数据库格式校验失败，已放弃下载: %s\n", dbInfo.Name, dbInfo.File)
		return errors.New("数据库内容出错")
	}

	policy := validate.LoadPolicy()
	if !policy.Enabled {
		if err := common.SaveFile(dbInfo.File, data); err != nil {
			log.Println("数据库保存失败:", err)
			return err
		}
		log.Printf("%s 数据库已更新（内容校验已关闭）: %s\n", dbInfo.Name, dbInfo.File)
		return nil
	}

	report, err := validate.Validate(dbInfo.Name, string(dbInfo.Format), data, dbInfo.File, policy)
	if err != nil {
		if errors.Is(err, validate.ErrUnsupported) {
			// No content validator for this format: fall back to format check.
			if err := common.SaveFile(dbInfo.File, data); err != nil {
				log.Println("数据库保存失败:", err)
				return err
			}
			log.Printf("%s 数据库下载成功（无内容校验器）: %s\n", dbInfo.Name, dbInfo.File)
			return nil
		}
		// Validator itself failed: be conservative and quarantine the bytes.
		dir, qErr := validate.StoreUnexpected(dbInfo.Name, string(dbInfo.Format), dbInfo.File, data, err)
		if qErr != nil {
			log.Printf("%s 校验过程异常且隔离失败，数据库未更新: %v\n", dbInfo.Name, err)
			return err
		}
		log.Printf("%s 校验过程异常，候选库已隔离，当前库保持不变: %s\n", dbInfo.Name, dir)
		log.Printf("可执行 `nali db report %s` 查看证据，确认无误后 `nali db activate %s`\n", dbInfo.Name, dbInfo.Name)
		return err
	}

	if report.Quarantined() {
		dir, err := validate.Store(report, data)
		if err != nil {
			log.Printf("%s 数据库未通过策略但隔离失败，当前库保持不变: %v\n", dbInfo.Name, err)
			return err
		}
		log.Printf("%s 候选库未通过内容策略，已隔离，当前库保持不变: %s\n", dbInfo.Name, dir)
		for _, c := range report.Checks {
			if c.Level == validate.LevelFail {
				log.Printf("  [失败] %s: %s\n", c.Name, c.Detail)
			}
		}
		log.Printf("可执行 `nali db report %s` 审阅采样证据，确认后 `nali db activate %s` 激活\n", dbInfo.Name, dbInfo.Name)
		return errors.New("数据库未通过内容策略，已进入隔离区")
	}

	if err := common.SaveFile(dbInfo.File, data); err != nil {
		log.Println("数据库保存失败:", err)
		return err
	}
	log.Printf("%s 数据库下载并通过内容校验: %s\n", dbInfo.Name, dbInfo.File)
	for _, c := range report.Checks {
		if c.Level == validate.LevelWarn {
			log.Printf("  [警告] %s: %s\n", c.Name, c.Detail)
		}
	}
	return nil
}

func getUpdateFuncByName(name string) (func() error, string) {
	name = strings.TrimSpace(name)
	if dbInfo := getDbByName(name); dbInfo != nil {
		// direct download if download-url not null
		if len(dbInfo.DownloadUrls) > 0 {
			return func() error {
				log.Printf("正在下载最新 %s 数据库...\n", dbInfo.Name)
				data, err := download.Fetch(dbInfo.DownloadUrls...)
				if err != nil {
					log.Printf("%s 数据库下载失败，请手动下载解压后保存到本地: %s \n", dbInfo.Name, dbInfo.File)
					log.Println("下载链接：", dbInfo.DownloadUrls)
					log.Println("error:", err)
					return err
				}
				return admitDownload(dbInfo, data)
			}, string(dbInfo.Format)
		}

		// internal download func
		switch dbInfo.Format {
		case FormatZXIPv6Wry:
			return func() error {
				log.Println("正在下载最新 ZX IPv6数据库...")
				data, err := zxipv6wry.FetchData()
				if err != nil {
					log.Println("数据库 ZXIPv6Wry 下载失败:", err)
					return err
				}
				return admitDownload(dbInfo, data)
			}, FormatZXIPv6Wry
		default:
			return func() error {
				log.Println("暂不支持该类型数据库的自动更新")
				log.Println("可通过指定数据库的 download-urls 从特定链接下载数据库文件")
				return nil
			}, time.Now().String()
		}
	} else {
		return func() error {
			log.Fatalln("该名称的数据库未找到：", name)
			return nil
		}, time.Now().String()
	}
}

package config

import (
	"log"

	"github.com/spf13/viper"
	"github.com/zu1k/nali/internal/db"
)

func ReadConfig(basePath string) {
	viper.SetDefault("databases", db.GetDefaultDBList())
	viper.SetDefault("selected.ipv4", "qqwry")
	viper.SetDefault("selected.ipv6", "zxipv6wry")
	viper.SetDefault("selected.cdn", "cdn")
	viper.SetDefault("selected.lang", "zh-CN")

	// Content validation policy applied during `nali update`.
	viper.SetDefault("validate.enabled", true)
	viper.SetDefault("validate.sample-size", 1000)
	viper.SetDefault("validate.boundary-samples", 256)
	viper.SetDefault("validate.seed", 20240520)
	viper.SetDefault("validate.evidence-limit", 50)
	viper.SetDefault("validate.thresholds.max-conflict-rate", 0.0)
	viper.SetDefault("validate.thresholds.max-jump-rate", 0.05)
	viper.SetDefault("validate.thresholds.max-coverage-drop", 0.05)
	viper.SetDefault("validate.thresholds.max-reserved-mislabel-rate", 0.25)
	viper.SetDefault("validate.thresholds.max-anchor-mismatch-rate", 0.5)
	viper.SetDefault("validate.thresholds.min-coverage", 0.5)
	viper.SetDefault("validate.thresholds.max-invalid-regex", 0)
	viper.SetDefault("validate.thresholds.max-regex-complexity", 200)
	viper.SetDefault("validate.thresholds.forbid-dangerous-regex", true)
	viper.SetDefault("validate.thresholds.max-regex-match-ms", 50)
	viper.SetDefault("validate.thresholds.max-cdn-change-rate", 0.5)

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(basePath)
	err := viper.ReadInConfig()
	if err != nil {
		err = viper.SafeWriteConfig()
		if err != nil {
			panic(err)
		}
	}

	_ = viper.BindEnv("selected.ipv4", "NALI_DB_IP4")
	_ = viper.BindEnv("selected.ipv6", "NALI_DB_IP6")
	_ = viper.BindEnv("selected.cdn", "NALI_DB_CDN")
	_ = viper.BindEnv("selected.lang", "NALI_LANG")

	dbList := db.List{}
	err = viper.UnmarshalKey("databases", &dbList)
	if err != nil {
		log.Fatalln("Config invalid:", err)
	}

	db.NameDBMap.From(dbList)
	db.TypeDBMap.From(dbList)
}

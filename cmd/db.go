package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/zu1k/nali/internal/db"
	"github.com/zu1k/nali/internal/validate"
)

// dbCmd manages quarantined database candidates.
var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "inspect quarantined database candidates and activate them after review",
}

var dbListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "list active databases and quarantined candidates",
	Run: func(cmd *cobra.Command, args []string) {
		asJSON, _ := cmd.Flags().GetBool("json")
		quarantine, err := validate.List()
		if err != nil {
			fmt.Fprintln(os.Stderr, "读取隔离区失败:", err)
			os.Exit(1)
		}
		if asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(quarantine)
			return
		}

		known := allDBFiles()
		green := color.New(color.FgGreen)
		red := color.New(color.FgRed)
		yellow := color.New(color.FgYellow)

		printed := map[string]bool{}
		for name, file := range known {
			printed[name] = true
			fmt.Printf("● %s (%s)\n", green.Sprint(name), file)
			if info, err := os.Stat(file); err == nil {
				fmt.Printf("    active: %s, %d bytes\n", info.ModTime().Format(time.RFC3339), info.Size())
			} else {
				fmt.Printf("    active: %s\n", yellow.Sprint("未下载"))
			}
			for _, e := range quarantine[name] {
				printEntry(e, red, yellow)
			}
		}
		// Quarantined snapshots of databases no longer present in config.
		for name, entries := range quarantine {
			if printed[name] {
				continue
			}
			fmt.Printf("● %s %s\n", yellow.Sprint(name), yellow.Sprint("(配置中不存在)"))
			for _, e := range entries {
				printEntry(e, red, yellow)
			}
		}
		if len(quarantine) == 0 {
			fmt.Println("（隔离区为空）")
		}
	},
}

func printEntry(e validate.Entry, red, yellow *color.Color) {
	verdict := yellow.Sprint("unknown")
	failChecks := ""
	if e.Report != nil {
		if e.Report.Quarantined() {
			verdict = red.Sprint("QUARANTINE")
		} else {
			verdict = "PASS"
		}
		var fails []string
		for _, c := range e.Report.Checks {
			if c.Level == validate.LevelFail {
				fails = append(fails, c.Name)
			}
		}
		failChecks = strings.Join(fails, ",")
	}
	size := int64(0)
	if info, err := os.Stat(e.Payload); err == nil {
		size = info.Size()
	}
	fmt.Printf("    └─ [%s] %s  %d bytes  fails=[%s]\n", verdict, e.ID, size, failChecks)
}

var dbReportCmd = &cobra.Command{
	Use:   "report <db-name> [--id timestamp]",
	Short: "show the validation report and sampled evidence of a quarantined DB",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		id, _ := cmd.Flags().GetString("id")
		asJSON, _ := cmd.Flags().GetBool("json")
		e, err := validate.GetEntry(args[0], id)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if asJSON {
			data, _ := os.ReadFile(fmt.Sprintf("%s/report.json", e.Dir))
			fmt.Println(string(data))
			return
		}
		if e.Report == nil {
			fmt.Fprintln(os.Stderr, "报告读取失败:", e.ReportErr)
			os.Exit(1)
		}
		printReport(e.Report)
	},
}

var dbActivateCmd = &cobra.Command{
	Use:   "activate <db-name> [--id timestamp] [--yes]",
	Short: "review evidence and activate a quarantined database candidate",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		id, _ := cmd.Flags().GetString("id")
		assumeYes, _ := cmd.Flags().GetBool("yes")

		file, ok := allDBFiles()[name]
		if !ok {
			fmt.Fprintf(os.Stderr, "配置中找不到数据库 %s，拒绝激活（请先在 config.yaml 中声明）\n", name)
			os.Exit(1)
		}

		e, err := validate.GetEntry(name, id)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if e.Report == nil {
			fmt.Fprintln(os.Stderr, "报告读取失败:", e.ReportErr)
			os.Exit(1)
		}
		printReport(e.Report)

		if !assumeYes {
			if !confirm(fmt.Sprintf("确认将隔离版本 %s 激活为 %s ？该库存在上述未通过项，激活后将直接用于查询结果 [y/N]: ", e.ID, file)) {
				fmt.Println("已取消，候选库仍保留在隔离区。")
				return
			}
		}

		if err := validate.Activate(e, file); err != nil {
			fmt.Fprintln(os.Stderr, "激活失败:", err)
			os.Exit(1)
		}
		fmt.Printf("已激活: %s -> %s\n", e.Payload, file)
	},
}

func confirm(prompt string) bool {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}

func printReport(r *validate.Report) {
	red := color.New(color.FgRed)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	fmt.Printf("数据库:     %s (%s)\n", r.DBName, r.Format)
	fmt.Printf("文件:       %s  (%d bytes)\n", r.File, r.Size)
	fmt.Printf("SHA256:     %s\n", r.SHA256)
	if r.ActiveSHA256 != "" {
		fmt.Printf("旧库SHA256: %s\n", r.ActiveSHA256)
	}
	fmt.Printf("生成时间:   %s\n", r.GeneratedAt)
	verdict := green.Sprint(string(r.Verdict))
	if r.Quarantined() {
		verdict = red.Sprint(string(r.Verdict))
	}
	fmt.Printf("结论:       %s\n", verdict)

	fmt.Println("指标:")
	for k, v := range r.Summary {
		fmt.Printf("  - %s = %.4f\n", k, v)
	}
	fmt.Println("检查项:")
	for _, c := range r.Checks {
		mark := green.Sprint("PASS")
		switch c.Level {
		case validate.LevelFail:
			mark = red.Sprint("FAIL")
		case validate.LevelWarn:
			mark = yellow.Sprint("WARN")
		}
		fmt.Printf("  [%s] %s  %s\n", mark, c.Name, c.Detail)
		for k, v := range c.Metrics {
			fmt.Printf("        %s=%.4f\n", k, v)
		}
	}
	if len(r.Evidence) > 0 {
		fmt.Printf("采样证据（%d 条）:\n", len(r.Evidence))
		for _, ev := range r.Evidence {
			fmt.Printf("  - [%s] %s\n", ev.Kind, ev.Target)
			if ev.Expected != "" {
				fmt.Printf("      expected: %s\n", ev.Expected)
			}
			if ev.Actual != "" {
				fmt.Printf("      actual:   %s\n", ev.Actual)
			}
			if ev.Previous != "" {
				fmt.Printf("      previous: %s\n", ev.Previous)
			}
			if ev.Current != "" {
				fmt.Printf("      current:  %s\n", ev.Current)
			}
			if ev.Detail != "" {
				fmt.Printf("      detail:   %s\n", ev.Detail)
			}
		}
	}
}

// allDBFiles merges configured databases with built-in defaults.
func allDBFiles() map[string]string {
	out := map[string]string{}
	for _, d := range db.GetDefaultDBList() {
		out[d.Name] = d.File
	}
	for name, d := range db.NameDBMap {
		out[name] = d.File
	}
	return out
}

func init() {
	dbListCmd.Flags().Bool("json", false, "output as JSON")
	dbReportCmd.Flags().String("id", "", "quarantine snapshot id (defaults to latest)")
	dbReportCmd.Flags().Bool("json", false, "output raw report JSON")
	dbActivateCmd.Flags().String("id", "", "quarantine snapshot id (defaults to latest)")
	dbActivateCmd.Flags().Bool("yes", false, "skip the confirmation prompt")

	dbCmd.AddCommand(dbListCmd)
	dbCmd.AddCommand(dbReportCmd)
	dbCmd.AddCommand(dbActivateCmd)
	rootCmd.AddCommand(dbCmd)
}

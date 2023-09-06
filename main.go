package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"os"
	"regexp"
	"strings"
)

var (
	sep   string
	num   int
	reg   string
	rl    bool
	debug bool
)

func init() {
	flag.StringVar(&sep, "sep", " ", "split分割符")
	flag.IntVar(&num, "num", 0, "split分割后的第几个元素，开始为0")
	flag.StringVar(&reg, "reg", "", "正则表达式，筛选结果符合正则的再输出。常用正则输入-l查看。")
	flag.BoolVar(&debug, "debug", false, "在重定向的同时，是否显示管道输入")
	flag.BoolVar(&rl, "l", false, "常用正则表达式")

	flag.Parse()
}

func printReg() {
	fmt.Println("========================= 对重定向结果进行处理后再输出  ==========================")
	fmt.Println(`[提取IP] echo "127.0.0.1:8080,127.0.0.1,title" | xee -sep "," -num 1`)
	fmt.Println(`[正则] echo "{IP:127.0.0.1,Time:xxxxx,Location:xxx}" | xee -sep "," -reg "((?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d))"`)
	fmt.Println("============================================================================\n")
	fmt.Printf("%s -> %s\n", "ip", "((?:(?:25[0-5]|2[0-4]\\d|[01]?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d?\\d)")
	fmt.Printf("%s -> %s\n", "域名", "[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+\\.?")
	fmt.Printf("%s -> %s\n", "IP:端口", "((?:(?:25[0-5]|2[0-4]\\d|[01]?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d?\\d):[0-9]d*.*")
	fmt.Printf("%s -> %s\n", "url", "http://([w-]+.)+[w-]+(/[w-./?%&=]*)?$")
	fmt.Printf("%s -> %s\n", "email", "w+([-+.]w+)*@w+([-.]w+)*.w+([-.]w+)*")
	fmt.Printf("%s -> %s\n", "手机号", "((13[0-9])|(14[0-9])|(15[0-9])|(17[0-9])|(18[0-9]))\\d{8}$")
	fmt.Printf("%s -> %s\n", "身份证", "(\\d{15}$)|(^\\d{17}([0-9]|X|x)$)")
	fmt.Printf("%s -> %s\n", "匹配由26个英文字母组成的字符串", "[A-Za-z]+$")
	fmt.Printf("%s -> %s\n", "匹配由26个大写英文字母组成的字符串", "[A-Z]+$")
	fmt.Printf("%s -> %s\n", "匹配由26个小写英文字母组成的字符串", "[a-z]+$")
	fmt.Printf("%s -> %s\n", "匹配由数字和26个英文字母组成的字符串", "[A-Za-z0-9]+$")
	fmt.Printf("%s -> %s\n", "匹配正整数", "[0-9]d*$")
}

func hasStdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	mode := stat.Mode()

	isPipedFromChrDev := (mode & os.ModeCharDevice) == 0
	isPipedFromFIFO := (mode & os.ModeNamedPipe) != 0

	return isPipedFromChrDev || isPipedFromFIFO
}

func main() {
	if rl {
		printReg()
	}
	if hasStdin() {
		scanner := bufio.NewScanner(os.Stdin)
		bufwriter := bufio.NewWriter(os.Stdout)
		sb := &strings.Builder{}
		for scanner.Scan() {
			target := strings.TrimSpace(scanner.Text()) //每一行的输入
			if debug {
				gologger.Info().Label("xee_dbg").Msg(target)
			}
			result := strings.Split(target, sep)
			if len(result) > num {
				//处理正则
				if reg != "" {
					pattern := regexp.MustCompile(reg)
					match := pattern.FindAllString(result[num], -1)
					if len(match) > 0 {
						sb.WriteString(match[0])
						bufwriter.WriteString(sb.String())
						bufwriter.Flush()
					}
					sb.Reset()
				} else {
					sb.WriteString(result[num])
					bufwriter.WriteString(sb.String())
					bufwriter.Flush()
					sb.Reset()
				}
			}
		}
		os.Stdin.Close()
		os.Stdout.Close()
	}
}

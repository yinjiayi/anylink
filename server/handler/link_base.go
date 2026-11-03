package handler

import (
	"encoding/xml"
	"os/exec"
	"syscall"

	"github.com/bjdgyc/anylink/base"
)

const BufferSize = 2048

type ClientRequest struct {
	XMLName              xml.Name       `xml:"config-auth"`
	Client               string         `xml:"client,attr"`                 // 一般都是 vpn
	Type                 string         `xml:"type,attr"`                   // 请求类型 init logout auth-reply
	AggregateAuthVersion string         `xml:"aggregate-auth-version,attr"` // 一般都是 2
	Version              string         `xml:"version"`                     // 客户端版本号
	GroupAccess          string         `xml:"group-access"`                // 请求的地址
	GroupSelect          string         `xml:"group-select"`                // 选择的组名
	RemoteAddr           string         `xml:"remote_addr"`
	UserAgent            string         `xml:"user_agent"`
	SessionId            string         `xml:"session-id"`
	SessionToken         string         `xml:"session-token"`
	Auth                 auth           `xml:"auth"`
	DeviceId             deviceId       `xml:"device-id"`
	MacAddressList       macAddressList `xml:"mac-address-list"`
	Capabilities         struct {
		AuthMethods []string `xml:"auth-method"`
	} `xml:"capabilities"`
	Opaque struct {
		SSOChallenge string `xml:"sso-session-id"`
		Group        string `xml:"tunnel-group"`
	} `xml:"opaque"`
}

type auth struct {
	Username          string `xml:"username"`
	Password          string `xml:"password"`
	OtpSecret         string `xml:"otp_secret"`
	SecondaryPassword string `xml:"secondary_password"`
	SsoToken          string `xml:"sso-token"`
}

type deviceId struct {
	ComputerName    string `xml:"computer-name,attr"`
	DeviceType      string `xml:"device-type,attr"`
	PlatformVersion string `xml:"platform-version,attr"`
	UniqueId        string `xml:"unique-id,attr"`
	UniqueIdGlobal  string `xml:"unique-id-global,attr"`
}

type macAddressList struct {
	MacAddress string `xml:"mac-address"`
}

func execCmd(cmdStrs []string) error {
	for _, cmdStr := range cmdStrs {
		cmd := exec.Command("sh", "-c", cmdStr)
		b, err := cmd.CombinedOutput()
		if err != nil {
			base.Error(cmdStr, string(b))
			return err
		}
	}
	return nil
}

// copy from  unix.KernelVersion()
func kernelVersion() (major, minor int) {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return
	}

	var (
		values    [2]int
		value, vi int
	)
	for _, c := range uname.Release {
		if '0' <= c && c <= '9' {
			value = (value * 10) + int(c-'0')
		} else {
			// Note that we're assuming N.N.N here.
			// If we see anything else, we are likely to mis-parse it.
			values[vi] = value
			vi++
			if vi >= len(values) {
				break
			}
			value = 0
		}
	}

	return values[0], values[1]
}

//内核版本	nftables 支持情况
//3.13+	基础支持（首次引入）
//4.1+	支持 masquerade, redirect
//4.2+	支持 nat, mangle 表
//4.3+	支持完整 NAT 功能
//4.10+	支持状态超时配置
//4.18+	完整功能支持（推荐）
//5.0+	性能优化和 bug 修复
//5.10+	企业级稳定支持（生产推荐）

// nftables 支持的内核版本
// 最低可用：Linux 3.13
// 推荐使用：Linux 4.18+
// 生产环境：Linux 5.10+
func supportsNftables() bool {
	major, minor := kernelVersion()

	// 需要 4.18+ 才有完整支持
	if major > 4 {
		return true
	}
	if major == 4 && minor >= 19 {
		return true
	}
	return false
}

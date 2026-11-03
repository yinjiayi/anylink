package handler

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/bjdgyc/anylink/base"
	"github.com/bjdgyc/anylink/dbdata"
	"github.com/bjdgyc/anylink/pkg/utils"
)

// ToDo:手机浏览器调起App验证
// 测试企微手机浏览器无法调起app,可按现有SAML认证流程接入其他OAuth2 （飞书、钉钉等）认证
func getServerAddr(r *http.Request) string {
	return "https://" + r.Host
}
func SAMLSPLogin(w http.ResponseWriter, r *http.Request) {
	tgname := r.URL.Query().Get("tgname")
	if tgname == "" {
		base.Error("缺少组名参数")
		return
	}
	// 获取企微配置
	wxworkConfig, err := dbdata.GetAuthWework(tgname)
	if err != nil {
		base.Error("获取企微配置失败", err)
		return
	}
	corpId := wxworkConfig.CorpId
	agentId := wxworkConfig.AgentId

	// 企微认证回调地址
	redirectUri := fmt.Sprintf("%s/WXAuth/callback", getServerAddr(r))
	wxWorkUrl := fmt.Sprintf("https://login.work.weixin.qq.com/wwlogin/sso/login?login_type=CorpApp&appid=%s&agentid=%s&redirect_uri=%s&state=%s",
		corpId, agentId, url.QueryEscape(redirectUri), url.QueryEscape(utils.RandomRunes(32)+tgname), // 使用state传递组名,添加随机字符防止CSRF 攻击
	)
	// ToDo: 移动设备调起App【未完成】
	// if isMobileDevice(r) {
	// 	wxWorkUrl = fmt.Sprintf(
	// 		"https://open.weixin.qq.com/connect/oauth2/authorize?appid=%s&redirect_uri=%s&response_type=code&scope=snsapi_base&state=%s&agentid=AGENTID#wechat_redirect",
	// 		corpId,
	// 		url.QueryEscape(redirectUri),
	// 		url.QueryEscape(utils.RandomRunes(32)+tgname),
	// 	)
	// }
	// 重定向到企业微信扫码页面
	http.Redirect(w, r, wxWorkUrl, http.StatusFound)
}

func WXAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state") // 通过state参数获取组名

	if code == "" || state == "" {
		base.Error("企微认证回调缺少参数")
		return
	}
	groupname := state[32:]
	// 获取企微配置
	wxworkConfig, err := dbdata.GetAuthWework(groupname)
	if err != nil {
		base.Error("获取企微配置失败", err)
		return
	}
	// 调用企业微信 API 获取用户信息
	userID, err := wxworkConfig.GetWeworkUser(wxworkConfig.CorpId, wxworkConfig.Secret, code)
	if err != nil {
		base.Error("用户信息获取失败", err)
		SAMLError(w, r, err)
		return
	}
	username := userID

	// 创建SAML会话 用于传递组名和用户名
	samlSession := &AuthSession{
		ClientRequest: &ClientRequest{
			GroupSelect: groupname,
			Auth: auth{
				Username: username,
			},
		},
	}
	// 保存saml会话，使用 state 作为 token（因为 state 包含了组名信息，更方便客户端使用）
	SessStore.SaveAuthSession(state, samlSession)

	// 设置 Cookie
	// 对state进行Base64编码后再设置Cookie
	encodeState := base64.StdEncoding.EncodeToString([]byte(state))
	SetCookie(w, "acSamlv2Token", encodeState, 0)

	// 重定向到 sso-v2-login-final URL（需严格符合cisco anyconnect路由格式，不允许带任何参数！）
	http.Redirect(w, r, "/+CSCOE+/saml_ac_login.html", http.StatusFound)
}

// SAML回调端点 - 对应 sso-v2-login-final
func SAMLACLogin(w http.ResponseWriter, r *http.Request) {
	if marker, err := r.Cookie("anylink-sso-finish"); err == nil && marker.Value == "1" {
		SSODone(w, r)
		return
	}
	// 验证 Cookie 是否存在
	encodeToken, err := GetCookie(r, "acSamlv2Token")
	if err != nil || encodeToken == "" {
		base.Error("认证信息丢失,获取Cookie失败")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("认证失败：无法获取认证信息"))
		return
	}
	// Base64解码
	tokenBytes, err := base64.StdEncoding.DecodeString(encodeToken)
	if err != nil {
		base.Error("Cookie解码失败", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	token := string(tokenBytes)
	if isAnyConnectInternalBrowser(r) {
		// AnyConnect 内置浏览器
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(html))
		return
	}
	// 获取返回URL（客户端本地监听地址），如果没有则使用当前页面
	returnURL := r.URL.Query().Get("return")
	if returnURL == "" {
		// 返回认证成功页面
		returnURL = fmt.Sprintf("%s/+CSCOE+/saml/sp/done", getServerAddr(r))
	}
	// 构造客户端本地API地址（用于external浏览器模式）
	// 客户端会在本地启动HTTP服务器监听此端口
	localAPIURL := fmt.Sprintf("http://localhost:29786/api/sso/%s?return=%s",
		url.QueryEscape(token),
		url.QueryEscape(returnURL))
	http.Redirect(w, r, localAPIURL, http.StatusFound)
}
func SAMLDone(w http.ResponseWriter, r *http.Request) {
	// 这个页面只负责显示成功的消息
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

func SAMLTest(w http.ResponseWriter, r *http.Request) {
	content := base.Cfg.WexinWorkVerifyFileContent
	w.Write([]byte(content))
}

// 判断是否为移动设备
func isMobileDevice(r *http.Request) bool {
	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" {
		return false
	}
	mobileKeywords := []string{"Mobile", "Android", "iPhone", "iPad", "iPod"}
	// 排除同时包含 Mobile 和 Desktop 的情况，如:开启了桌面模式
	for _, keyword := range mobileKeywords {
		if strings.Contains(userAgent, keyword) {
			return true
		}
	}

	return false
}

// 判断是否是AnyConnect内置浏览器
func isAnyConnectInternalBrowser(r *http.Request) bool {
	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" {
		return false
	}
	if strings.Contains(userAgent, "AnyConnect") {
		return true
	}
	return false
}

var auth_request_saml = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
    <opaque is-for="sg">
        <tunnel-group>{{.Group}}</tunnel-group>
        <group-alias>{{.Group}}</group-alias>
        <aggauth-handle>168179266</aggauth-handle>
        <config-hash>1595829378234</config-hash>
        <auth-method>single-sign-on-v2</auth-method>
    </opaque>
    <auth id="main">
        <title>SAML SSO Login</title>
        <message>请完成SAML单点登录认证</message>
        <banner></banner>
        {{if .Error}}
        <error id="88" param1="{{.Error}}" param2="">SAML认证失败: %s</error>
        {{end}}
        <sso-v2-login>{{.ServerAddr}}/+CSCOE+/saml/sp/login?tgname={{.Group}}&#x26;acsamlcap=v2</sso-v2-login>
        <sso-v2-login-final>{{.ServerAddr}}/+CSCOE+/saml_ac_login.html</sso-v2-login-final>
        <sso-v2-token-cookie-name>acSamlv2Token</sso-v2-token-cookie-name>
        {{if .BrowserMode}}<sso-v2-browser-mode>{{.BrowserMode}}</sso-v2-browser-mode>{{end}}
        <form>
            <input type="sso" name="sso-token"></input>
        </form>
    </auth>
</config-auth>`

// 注释说明：
// 调用外部浏览器需加入
// {{if .BrowserMode}}<sso-v2-browser-mode>{{.BrowserMode}}</sso-v2-browser-mode>{{end}}
// <sso-v2-browser-mode> 标签用于控制浏览器打开方式：
//   - "external": 使用系统默认浏览器打开认证页面
//   - 不设置或为空: 使用 AnyConnect 客户端内置浏览器
// 其他可用但未使用的标签：
// <sso-v2-error-cookie-name>acSamlv2Error</sso-v2-error-cookie-name>

var html = `
<!DOCTYPE html>
<html>
<head>
    <title>认证成功 - 请关闭</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #f5f5f5;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.2);
            padding: 40px;
            max-width: 450px;
            width: 100%;
            text-align: center;
        }
        .icon {
            font-size: 56px;
            color: #4CAF50; 
            margin-bottom: 24px;
        }
        h1 {
            color: #303133;
            font-size: 28px;
            margin-bottom: 15px;
        }
        .detail {
            color: #606266;
            font-size: 15px;
            margin-bottom: 25px;
        }
        .note {
            color: #909399;
            font-size: 13px;
            margin-top: 30px;
            border-top: 1px solid #e4e7ed;
            padding-top: 20px;
        }
    </style>
    <script>
        function tryCloseWindow() {
            window.close(); 
            setTimeout(function() {
                alert("如果窗口未关闭，请手动关闭此页面并返回您的客户端。");
            }, 50); 
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="icon">✅</div>
        <h1>认证成功！</h1>
        <p class="detail">已成功通过企业微信认证，VPN客户端将自动完成连接。</p>
        <p class="detail">
            请返回 AnyConnect 客户端查看连接状态。
        </p>
        <div class="note">
            提示：由于浏览器安全限制，网页无法自动关闭非脚本打开的窗口。
            请手动关闭此页面以完成认证流程。
        </div>
    </div>
</body>
</html>`

func SAMLError(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	errorPage := `
<!DOCTYPE html>
<html>
<head>
    <title>认证失败</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #f5f5f5;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.2);
            padding: 40px;
            max-width: 450px;
            width: 100%;
            text-align: center;
        }
        .icon {
            font-size: 56px;
            color: #f44336; 
            margin-bottom: 24px;
        }
        h1 {
            color: #303133;
            font-size: 24px;
            margin-bottom: 15px;
        }
        .error-message {
            color: #e6a23c;
            font-size: 16px;
            margin-bottom: 20px;
        }
        .detail {
            color: #606266;
            font-size: 15px;
            margin-bottom: 25px;
        }
        .note {
            color: #909399;
            font-size: 13px;
            margin-top: 30px;
            border-top: 1px solid #e4e7ed;
            padding-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">❌</div>
        <h1>认证失败</h1>
        <div class="error-message">` + err.Error() + `</div>
        <p class="detail">请确认您所在的部门是否在允许的范围内，或联系管理员解决。</p>
        <div class="note">
            提示：由于浏览器安全限制，网页可能无法自动关闭。<br>
            请手动关闭此页面并返回 AnyConnect 客户端。
        </div>
    </div>
</body>
</html>`
	w.Write([]byte(errorPage))
}

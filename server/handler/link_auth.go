package handler

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"text/template"

	"github.com/bjdgyc/anylink/base"
	"github.com/bjdgyc/anylink/dbdata"
	"github.com/bjdgyc/anylink/sessdata"
)

var (
	profileHash = ""
	certHash    = ""
)

func LinkAuth(w http.ResponseWriter, r *http.Request) {
	// Do not dump authentication bodies: they contain passwords and SSO tickets.
	// 判断anyconnect客户端
	userAgent := strings.ToLower(r.UserAgent())
	xAggregateAuth := r.Header.Get("X-Aggregate-Auth")
	xTranscendVersion := r.Header.Get("X-Transcend-Version")
	if !((strings.Contains(userAgent, "anyconnect") || strings.Contains(userAgent, "openconnect") || strings.Contains(userAgent, "anylink")) &&
		xAggregateAuth == "1" && xTranscendVersion == "1") {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "error request")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128<<10))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	cr := &ClientRequest{
		RemoteAddr: r.RemoteAddr,
		UserAgent:  userAgent,
	}
	err = xml.Unmarshal(body, &cr)
	if err != nil {
		base.Error(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := browserSSONegotiations.remember(w, r, cr); err != nil {
		ssoError(w, http.StatusBadRequest)
		return
	}
	// 用户活动日志
	ua := &dbdata.UserActLog{
		Username:        cr.Auth.Username,
		GroupName:       cr.GroupSelect,
		RemoteAddr:      r.RemoteAddr,
		Status:          dbdata.UserAuthSuccess,
		DeviceType:      cr.DeviceId.DeviceType,
		PlatformVersion: cr.DeviceId.PlatformVersion,
	}

	// setCommonHeader(w)
	if cr.Type == "logout" {
		// 退出删除session信息
		if cr.SessionToken != "" {
			sessdata.DelSessByStoken(cr.SessionToken)
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	sessionData := &AuthSession{
		ClientRequest: cr,
		UserActLog:    ua,
	}
	// 处理客户端的特殊情况
	// Cisco AnyConnect 移动端在验证失败后会发送空用户组请求，会导致验证死循环从而防爆逻辑失效
	// OpenConnect 在某些连接阶段也需要发送空组请求，不能直接拒绝
	// SSO 认证（如企业微信）可能在认证初期也带有空组，需要特别处理
	if cr.GroupSelect == "" {
		// Cisco AnyConnect 移动端在发起连接请求时，会发送空用户组
		if cr.Auth.SsoToken != "" || cr.Type == "init" || cr.Opaque.SSOChallenge != "" {
		} else if !strings.Contains(userAgent, "openconnect") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	// 锁定状态判断
	if !lockManager.CheckLocked(cr.Auth.Username, r.RemoteAddr) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// New browser SSO has its own single-use store; never send its tickets to
	// the legacy WeCom/OTP session store or allow password/certificate fallback.
	if cr.Opaque.SSOChallenge != "" {
		if cr.Type != "auth-reply" || cr.Auth.SsoToken == "" || base.Cfg.AuthOnlyCert {
			ssoError(w, http.StatusForbidden)
			return
		}
		browserSSO.redeem(w, r, cr, ua)
		return
	}
	if isBrowserSSOGroup(cr.GroupSelect) {
		cfg, err := browserSSO.loadConfig(cr.GroupSelect)
		if err != nil || base.Cfg.AuthOnlyCert || cr.Auth.SsoToken != "" ||
			(cr.Type != "init" && cr.Type != "auth-reply") {
			ssoError(w, http.StatusForbidden)
			return
		}
		browserSSO.begin(w, r, cr, cfg)
		return
	}
	// 检查客户端证书认证
	if base.Cfg.AuthCert {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			clientCert := r.TLS.PeerCertificates[0]
			username := clientCert.Subject.CommonName
			if len(clientCert.Subject.OrganizationalUnit) == 0 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			groupname := clientCert.Subject.OrganizationalUnit[0]
			if username == "" || groupname == "" {
				base.Warn("客户端证书缺少用户名或组名")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if isBrowserSSOGroup(groupname) {
				// A certificate for a group switched to SSO cannot bypass its IdP.
				ssoError(w, http.StatusForbidden)
				return
			}
			ua.Username = username
			ua.GroupName = groupname
			// 验证证书有效性和用户状态
			if dbdata.ValidateClientCert(clientCert, cr.DeviceId.UniqueIdGlobal) {
				// 证书认证成功，创建会话
				base.Info("用户通过证书认证:", username)

				sessionData.ClientRequest.GroupSelect = groupname
				sessionData.ClientRequest.Auth.Username = username
				ua.Info = "用户通过证书认证登录"
				ua.Status = dbdata.UserConnected
				dbdata.UserActLogIns.Add(*ua, userAgent)

				CreateSession(w, r, sessionData)
				return
			} else {
				ua.Info = "客户端证书验证失败"
				ua.Status = dbdata.UserAuthFail
				dbdata.UserActLogIns.Add(*ua, userAgent)
				if base.Cfg.AuthOnlyCert {
					base.Warn("已开启仅证书验证，但客户端证书验证失败,拒绝访问")
					return
				}
				base.Warn("已开启证书验证，但客户端证书验证失败,回退到用户名密码验证")
			}
		} else {
			if base.Cfg.AuthOnlyCert {
				base.Warn("已开启仅证书验证，但客户端未提供有效证书,拒绝访问")
				w.WriteHeader(http.StatusForbidden)
				return
			}
			base.Warn("已开启证书验证，但客户端未提供有效证书,回退到用户名密码验证")
		}
	}

	if cr.Type == "init" {
		// 处理 OpenConnect 客户端的组选择优化
		// OpenConnect 客户端在连接过程中可能出现重复组选择的问题：
		// 1. OpenConnect 在初始连接时可能已经携带了组信息
		// 2. 但在后续的认证流程中，客户端又会显示组选择界面
		// 3. 这导致用户需要选择两次相同的组
		//
		// 解决方案：
		// 当检测到是 OpenConnect 客户端且已经有组选择时，
		// 只显示当前已选择的组，避免重复选择组
		if cr.GroupSelect != "" && strings.Contains(userAgent, "openconnect") {
			data := RequestData{
				Group:  cr.GroupSelect,
				Groups: []string{cr.GroupSelect},
			}
			w.WriteHeader(http.StatusOK)
			tplRequest(tpl_request, w, data)
			return
		}
		// 获取组配置信息
		groupData := &dbdata.Group{}
		err := dbdata.One("Name", cr.GroupSelect, groupData)
		if err == nil && len(groupData.Auth) > 0 {
			authType := groupData.Auth["type"].(string)
			if authType == "wxwork" {
				// 获取企业微信配置，检查是否使用默认浏览器
				wxworkConfig, err := dbdata.GetAuthWework(cr.GroupSelect)
				var browserMode string
				if err == nil && wxworkConfig.UseDefaultBrowser {
					browserMode = "external" // 使用系统默认浏览器
				}
				// 暂时仅支持PC端Cisco Anyconnect客户端
				if isMobileDevice(r) || strings.Contains(userAgent, "openconnect") {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				// 使用企微认证模板
				data := RequestData{
					Group:       url.QueryEscape(cr.GroupSelect),
					Groups:      dbdata.GetGroupNamesNormal(),
					ServerAddr:  getServerAddr(r),
					BrowserMode: browserMode,
				}
				w.WriteHeader(http.StatusOK)
				tplRequest(tpl_request_saml, w, data)
				return
			}
		}
		data := RequestData{Group: cr.GroupSelect, Groups: dbdata.GetGroupNamesNormal()}
		w.WriteHeader(http.StatusOK)
		tplRequest(tpl_request, w, data)
		return
	}

	// 登陆参数判断
	if cr.Type != "auth-reply" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if cr.Auth.SsoToken != "" {
		base.Info("处理SSO认证请求")
		decodeToken := cr.Auth.SsoToken
		// base64解码Token
		if tokenBytes, err := base64.StdEncoding.DecodeString(cr.Auth.SsoToken); err == nil {
			decodeToken = string(tokenBytes)
		}
		// 获取saml会话
		samlSession, err := SessStore.GetAuthSession(decodeToken)
		if err != nil {
			base.Error("会话不存在")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Legacy SSO may only complete a currently enabled WeCom group.
		legacyGroup := &dbdata.Group{}
		if dbdata.One("Name", samlSession.ClientRequest.GroupSelect, legacyGroup) != nil ||
			legacyGroup.Status != 1 || legacyGroup.Auth["type"] != "wxwork" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// 修改客户端请求中的用户信息
		cr.Auth.Username = samlSession.ClientRequest.Auth.Username
		cr.GroupSelect = samlSession.ClientRequest.GroupSelect

		// 更新用户活动日志
		ua.Username = samlSession.ClientRequest.Auth.Username
		ua.GroupName = samlSession.ClientRequest.GroupSelect
		ua.Info = "用户通过企微认证登录"

		sessionData.ClientRequest = cr
		sessionData.UserActLog = ua

		dbdata.UserActLogIns.Add(*ua, userAgent)
		// 创建会话
		CreateSession(w, r, sessionData)
		// 删除saml会话
		SessStore.DeleteAuthSession(cr.Auth.SsoToken)
		return
	}

	// TODO 用户密码校验
	ext := map[string]any{"mac_addr": cr.MacAddressList.MacAddress}
	err = dbdata.CheckUser(cr.Auth.Username, cr.Auth.Password, cr.GroupSelect, ext)
	if err != nil {
		lockManager.UpdateLoginStatus(cr.Auth.Username, r.RemoteAddr, false) // 记录登录失败状态

		base.Warn(err, r.RemoteAddr)
		ua.Info = err.Error()
		ua.Status = dbdata.UserAuthFail
		dbdata.UserActLogIns.Add(*ua, userAgent)

		w.WriteHeader(http.StatusOK)
		data := RequestData{Group: cr.GroupSelect, Groups: dbdata.GetGroupNamesNormal(), Error: "用户名或密码错误"}
		if base.Cfg.DisplayError {
			data.Error = err.Error()
		}
		tplRequest(tpl_request, w, data)
		return
	}
	v := &dbdata.User{}
	err = dbdata.One("Username", cr.Auth.Username, v)
	if err != nil {
		base.Info("正在使用第三方认证方式登录")
	} else {
		// 用户otp验证
		if base.Cfg.AuthAloneOtp && !v.DisableOtp {
			lockManager.UpdateLoginStatus(cr.Auth.Username, r.RemoteAddr, true) // 重置OTP验证计数

			sessionID, err := GenerateSessionID()
			if err != nil {
				base.Error("Failed to generate session ID: ", err)
				http.Error(w, "Failed to generate session ID", http.StatusInternalServerError)
				return
			}

			sessionData.ClientRequest.Auth.OtpSecret = v.OtpSecret
			SessStore.SaveAuthSession(sessionID, sessionData)

			SetCookie(w, "auth-session-id", sessionID, 0)
			if base.Cfg.SendOtp {
				go func(username string) {
					if err := SendOtpToUser(username); err != nil {
						base.Error("发送OTP验证码错误: ", err)
						return
					}
					base.Info(username, "OTP验证码已发送")
				}(cr.Auth.Username)
			}

			data := RequestData{}
			w.WriteHeader(http.StatusOK)
			tplRequest(tpl_otp, w, data)
			return
		}
	}
	dbdata.UserActLogIns.Add(*ua, userAgent)
	CreateSession(w, r, sessionData)
}

const (
	tpl_request = iota
	tpl_complete
	tpl_otp
	tpl_request_saml
)

func tplRequest(typ int, w io.Writer, data RequestData) {
	switch typ {
	case tpl_request:
		t, _ := template.New("auth_request").Parse(auth_request)
		_ = t.Execute(w, data)
	case tpl_complete:
		if data.Banner != "" {
			buf := new(bytes.Buffer)
			_ = xml.EscapeText(buf, []byte(data.Banner))
			data.Banner = buf.String()
		}
		t, _ := template.New("auth_complete").Parse(auth_complete)
		_ = t.Execute(w, data)
	case tpl_otp:
		t, _ := template.New("auth_otp").Parse(auth_otp)
		_ = t.Execute(w, data)
	case tpl_request_saml:
		t, _ := template.New("auth_request_saml").Parse(auth_request_saml)
		_ = t.Execute(w, data)
	}
}

// 设置输出信息
type RequestData struct {
	Groups []string
	Group  string
	Error  string

	// complete
	SessionId    string
	SessionToken string
	Banner       string
	ProfileName  string
	ProfileHash  string
	CertHash     string

	// saml
	ServerAddr  string
	BrowserMode string // 浏览器模式: "external"=使用默认浏览器, ""=使用内置浏览器
}

var auth_request = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
    <opaque is-for="sg">
        <tunnel-group>{{.Group}}</tunnel-group>
        <group-alias>{{.Group}}</group-alias>
        <aggauth-handle>168179266</aggauth-handle>
        <config-hash>1595829378234</config-hash>
        <auth-method>multiple-cert</auth-method>
        <auth-method>single-sign-on-v2</auth-method>
    </opaque>
    <auth id="main">
        <title>Login</title>
        <message>请输入你的用户名和密码</message>
        <banner></banner>
        {{if .Error}}
        <error id="88" param1="{{.Error}}" param2="">登陆失败:  %s</error>
        {{end}}
        <form>
            <input type="text" name="username" label="Username:"></input>
            <input type="password" name="password" label="Password:"></input>
            <select name="group_list" label="GROUP:">
                {{range $v := .Groups}}
                <option {{if eq $v $.Group}} selected="true"{{end}}>{{$v}}</option>
                {{end}}
            </select>
        </form>
    </auth>
</config-auth>
`

var auth_complete = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
    <session-id>{{.SessionId}}</session-id>
    <session-token>{{.SessionToken}}</session-token>
    <auth id="success">
        <banner>{{.Banner}}</banner>
        <message id="0" param1="" param2=""></message>
    </auth>
    <capabilities>
        <crypto-supported>ssl-dhe</crypto-supported>
    </capabilities>
    <config client="vpn" type="private">
        <vpn-base-config>
            <server-cert-hash>{{.CertHash}}</server-cert-hash>
        </vpn-base-config>
        <opaque is-for="vpn-client"></opaque>
        <vpn-profile-manifest>
            <vpn rev="1.0">
                <file type="profile" service-type="user">
                    <uri>/{{.ProfileName}}.xml</uri>
                    <hash type="sha1">{{.ProfileHash}}</hash>
                </file>
            </vpn>
        </vpn-profile-manifest>
    </config>
</config-auth>
`

// var auth_profile = `<?xml version="1.0" encoding="UTF-8"?>
// <AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://schemas.xmlsoap.org/encoding/ AnyConnectProfile.xsd">

// 	<ClientInitialization>
// 		<UseStartBeforeLogon UserControllable="false">false</UseStartBeforeLogon>
// 		<StrictCertificateTrust>false</StrictCertificateTrust>
// 		<RestrictPreferenceCaching>false</RestrictPreferenceCaching>
// 		<RestrictTunnelProtocols>IPSec</RestrictTunnelProtocols>
// 		<BypassDownloader>true</BypassDownloader>
// 		<WindowsVPNEstablishment>AllowRemoteUsers</WindowsVPNEstablishment>
// 		<CertEnrollmentPin>pinAllowed</CertEnrollmentPin>
// 		<CertificateMatch>
// 			<KeyUsage>
// 				<MatchKey>Digital_Signature</MatchKey>
// 			</KeyUsage>
// 			<ExtendedKeyUsage>
// 				<ExtendedMatchKey>ClientAuth</ExtendedMatchKey>
// 			</ExtendedKeyUsage>
// 		</CertificateMatch>

// 		<BackupServerList>
// 	            <HostAddress>localhost</HostAddress>
// 		</BackupServerList>
// 	</ClientInitialization>

//	<ServerList>
//		<HostEntry>
//	            <HostName>VPN Server</HostName>
//	            <HostAddress>localhost</HostAddress>
//		</HostEntry>
//	</ServerList>
//
// </AnyConnectProfile>
// `
var ds_domains_xml = `
<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
    <config client="vpn" type="private">
        <opaque is-for="vpn-client">
            <custom-attr>
            {{if .DsExcludeDomains}}
               <dynamic-split-exclude-domains><![CDATA[{{.DsExcludeDomains}},]]></dynamic-split-exclude-domains>
            {{else if .DsIncludeDomains}}
               <dynamic-split-include-domains><![CDATA[{{.DsIncludeDomains}}]]></dynamic-split-include-domains>
            {{end}}
            </custom-attr>
        </opaque>
    </config>
</config-auth>
`

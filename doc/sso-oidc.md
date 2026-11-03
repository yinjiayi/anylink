# OAuth2 / OpenID Connect 网页登录

AnyLink 在身份提供方（IdP）侧作为 OAuth2/OIDC 客户端，在 VPN 客户端侧使用 AnyConnect 网页 SSO 协议。用户选择启用 SSO 的用户组后，由客户端打开登录页面；验证完成后，客户端取得短期、一次性 VPN 票据，再建立 VPN 会话。

优先使用 OIDC：服务端验证 ID token 的签名、issuer、audience、有效期和 nonce。纯 OAuth2 没有统一的身份声明，只有在配置可信用户信息端点和稳定身份字段后才能用于本功能。两种模式均使用 Authorization Code + PKCE S256；不支持 implicit flow、密码授权或仅凭 access token 存在就放行。

## 配置前提

- VPN 外部地址及 IdP 各端点使用 HTTPS，证书必须受客户端/服务端信任。需要私有 CA 时，将 CA 安装到相应信任库，不关闭证书校验。
- VPN 网关能够访问 IdP 的 discovery、JWKS、token 或 userinfo 端点；用户浏览器能够访问 IdP 和 VPN 外部地址。
- 先创建 AnyLink 用户组和已有用户，确认用户已启用、未过期且属于待登录的用户组。
- 本功能不自动创建用户。每个组显式配置“IdP 稳定身份 → AnyLink 用户名”映射；空映射拒绝所有 SSO 用户。
- MFA、设备准入、passkey 等验证由 IdP 的认证策略执行。本 SSO 流程不追加 AnyLink 本地 TOTP。需要 MFA 时，应在 IdP 强制要求，而不能依赖 AnyLink 的本地用户 OTP 开关。
- 若全局启用了 `auth_only_cert`，本实现拒绝 SSO 登录，避免绕过仅证书策略。使用网页登录的部署应关闭该全局选项；普通证书登录也不能直接进入已改为 SSO 的组。
- 新配置将用户组的 `auth` 列改为 `TEXT`。升级前备份数据库；SQLite 新库已验证，已有 MySQL/PostgreSQL/MSSQL 环境应核验迁移后列类型和配置完整性，再启用较大的身份映射。不要将本次 SQLite 测试当作这些数据库的迁移验证。

## 注册 IdP 应用

注册一个用于服务端网页登录的应用：

1. 选择 OIDC / OAuth2 Authorization Code Flow，并启用 PKCE S256。
2. 将回调地址精确设置为：

   ```text
   https://vpn.example.com/+CSCOE+/sso/callback
   ```

   使用自定义端口时，回调地址必须带上同一端口。不要使用通配回调地址。
3. 记录 Client ID。对于机密客户端，从 IdP 获取 Client Secret，填入 AnyLink 管理界面；不要把真实密钥写入 Git 或示例配置。
4. OIDC 至少申请 `openid`；需要时可加 `profile`。不需要请求离线访问或刷新令牌权限。
5. 在 IdP 配置允许使用此应用的人员和所需 MFA 策略。

例如 Keycloak：创建 OpenID Connect 客户端，启用 Standard Flow，配置精确的 Valid Redirect URI，按需要开启客户端认证并配置 Secret，将 PKCE 方法设置为 S256。Issuer 使用该 realm 公布的值，例如 `https://login.example.com/realms/company`。具体管理界面以所用版本为准。[Keycloak 官方管理指南](https://www.keycloak.org/docs/26.7.0/server_admin/index.html)

AnyLink 向 IdP 注册的回调始终是上述 HTTPS 地址。`http://localhost:29786` 是部分 AnyConnect 客户端的本地外部浏览器回传地址，不应注册为 IdP 应用回调地址。

## 配置 AnyLink 用户组

在“用户组 → 编辑 → 认证方式”中选择 **OIDC** 或 **OAuth2**。

| 字段 | 说明 |
| --- | --- |
| VPN 外部地址 | 用户访问 VPN 的 HTTPS origin，如 `https://vpn.example.com` 或 `https://vpn.example.com:8443`，不带路径、查询参数或片段 |
| Issuer（OIDC） | 与 IdP discovery 和 ID token 中 issuer 完全一致；不是授权页面 URL |
| Client ID / Secret | IdP 应用凭据；公开客户端仅在 IdP 支持 PKCE 时可不配置 Secret |
| Scopes | 空格分隔，保存时为字符串数组；OIDC 必须包含 `openid` |
| 授权/令牌/用户信息端点（OAuth2） | 显式配置 IdP 的 HTTPS 端点 |
| 身份字段（OAuth2） | userinfo JSON 顶层的稳定唯一字符串或数字字段，如 `id`；不使用可修改的邮箱、用户名或显示名 |
| 浏览器模式 | `auto` 自动协商、`internal` 客户端内置浏览器、`external` 系统浏览器 |
| 用户身份映射 | JSON 对象，key 为 OIDC 的 `sub` 或 OAuth2 稳定身份字段值，value 为已有 AnyLink 用户名 |

OIDC 使用经验证的 `sub` 作为外部身份，不能用 `preferred_username` 或邮箱替代。相同 `sub` 只在所配置的 issuer 内有意义；更换 issuer 时必须重新核对该组映射。

用户身份映射示例：

```json
{
  "f28981c0-885f-4e99-9372-5384d91ed86e": "alice",
  "d9d95716-6d4a-42de-95df-8b45e78b43cf": "bob"
}
```

这些 subject 是格式示例。应通过 IdP 的受信管理界面或受保护的身份查询获取实际值，不将用户自行填写的 subject 当作授权依据。OAuth2 数字身份也作为 JSON key 字符串填写，如 `"123456": "alice"`。

保存后的组认证对象采用以下结构，可用于管理员 API 配置。Secret 留空是为了避免示例携带凭据；机密客户端部署时必须填写实际 Secret。

```json
{
  "type": "oidc",
  "oidc": {
    "issuer": "https://login.example.com/realms/company",
    "client_id": "anylink-vpn",
    "client_secret": "",
    "public_url": "https://vpn.example.com",
    "scopes": ["openid", "profile"],
    "browser_mode": "auto",
    "subject_users": {
      "f28981c0-885f-4e99-9372-5384d91ed86e": "alice"
    }
  }
}
```

纯 OAuth2 示例：

```json
{
  "type": "oauth2",
  "oauth2": {
    "client_id": "anylink-vpn",
    "client_secret": "",
    "public_url": "https://vpn.example.com",
    "authorization_url": "https://login.example.com/oauth/authorize",
    "token_url": "https://login.example.com/oauth/token",
    "userinfo_url": "https://login.example.com/api/user",
    "subject_claim": "id",
    "scopes": ["read:user"],
    "browser_mode": "auto",
    "subject_users": {
      "123456": "alice"
    }
  }
}
```

OAuth2 的 endpoint、scope、用户信息响应结构和 PKCE 支持因提供方而异；示例不能直接作为任意提供方的配置。此实现要求返回顶层 JSON 身份字段，不支持嵌套 claim 路径、GraphQL 查询或提供方专有签名参数。

映射用户在网页登录和 VPN 票据兑换时必须符合本地授权条件：用户和组启用、用户未过期、用户仍属于该组。认证成功不会绕过原有网络 ACL、路由和会话限制。停用用户或移除组成员资格后，应另按现有在线会话管理流程断开已经建立的连接；本功能不实现 IdP back-channel logout 或即时在线会话吊销。

## 浏览器与客户端兼容

- **auto**：依据客户端申报的 SSO 能力及外部浏览器公钥协商，不以浏览器 User-Agent 猜测模式。
- `auto` 仅在外部能力和有效 P-256 公钥同时存在时选外部浏览器；否则要求客户端声明内置 SSO v2 能力。显式 `external` 缺少能力或合法公钥时拒绝，不回传明文票据。
- **internal**：使用 AnyConnect SSO v2 内置浏览器，登录结束后由客户端提取专用短期 Cookie，再提交 VPN 票据。IdP 必须允许该客户端的 WebView 登录方式。
- **external**：使用系统浏览器，要求客户端支持外部 SSO 并提交 STRAP DH 公钥。AnyLink 使用 Cisco ECIES 格式加密一次性票据后回传本机客户端；不会将 IdP access token 或 ID token传给本地回调。

Cisco 官方在 AnyConnect 4.10.04065 起介绍较新的外部浏览器支持，Cisco 部署中还涉及外部 SSO 组件。第三方网关必须结合具体 Cisco Secure Client / AnyConnect 构建和系统平台实际测试。版本号达到要求本身不保证能用；也不承诺移动端、CLI 或 Start Before Logon 支持。[Cisco 4.10 发布说明](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/anyconnect410/release/notes/release-notes-anyconnect-4-10.html)、[Cisco 配置指南](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/anyconnect410/administration/guide/b-anyconnect-admin-guide-4-10/configure_vpn.html)

本 fork 的目标验收平台为 Windows、macOS、Linux、Android、iOS，均使用联调时最新稳定客户端。Cisco 的 [Android 4.10 发布说明](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/anyconnect410/release/notes/release-notes-android-anyconnect-4-10-.html)和 [iOS 4.10 发布说明](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/anyconnect410/release/notes/release-notes-apple-ios-anyconnect-4-10.html)也介绍了移动端 SAML 外部浏览器能力，因此本实现不会仅凭 Android/iOS 的 User-Agent 禁止该能力。这里实现的 localhost:29786 + Cisco ECIES 回传来自 OpenConnect 公开实现；其在各移动端当前构建的具体回传行为，仍须通过实机验证。客户端不申报能力时不会强行打开外部浏览器。

2026-11-03 的候选实机基线如下，表中版本尚未完成本 fork 的互通测试；实际测试时须再次确认最新稳定版本并记录具体构建号。

| 平台 | 官方资料中的当前 VPN 客户端基线 | 实测状态 |
| --- | --- | --- |
| Windows / macOS / Linux | [5.1.20.333](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/Cisco-Secure-Client-5/release/notes/release-notes-cisco-secure-client-5-1.html) | 待测 |
| Android | [5.1.15.344](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/Cisco-Secure-Client-5/release/notes/release-notes-secure-client-for-android-release-5-0.html) | 待测 |
| iOS / iPadOS | [5.1.16.264](https://apps.apple.com/us/app/cisco-secure-client/id1135064690) | 待测 |

macOS 应测试原生桌面客户端，不将 Mac 上的 iOS 应用当作同一构建。部分 Linux 发行版缺少所需 WebKitGTK，因此内置浏览器并非所有发行版都可用。移动端文档中的 Zero Trust Access 应用版本也不能代替 AnyConnect VPN 客户端版本。

OpenConnect 的外部浏览器支持还依赖版本、编译选项及运行方式。不要将一个带 WebView 的客户端验证结果推广为所有 OpenConnect 命令行版本可用。协议实现参考：[OpenConnect SSO 解析](https://gitlab.com/openconnect/openconnect/-/blob/70d1e79d1e55849dfc71dcc199b1edb535b547e4/auth.c)、[外部票据封包](https://gitlab.com/openconnect/openconnect/-/blob/70d1e79d1e55849dfc71dcc199b1edb535b547e4/hpke.c)。

客户端授权也影响最终选型：Cisco 发布的 [iOS App Store 说明](https://apps.apple.com/us/app/cisco-secure-client/id1135064690)及 [Android Google Play 说明](https://play.google.com/store/apps/details?id=com.cisco.anyconnect.vpn.android.avf)明确限制其客户端与非 Cisco 服务端/软件搭配使用。协议兼容实现不代表获得 Cisco 客户端的使用许可；实际部署需解决这一授权限制，或采用许可适用的兼容客户端。

## 登录和故障处理

1. 客户端连接 VPN，选择 OIDC/OAuth2 用户组。
2. 客户端打开 SSO 网页，用户在 IdP 完成登录及 MFA。
3. 页面回到 VPN 网关；内置浏览器自动结束，外部浏览器将加密票据交回本地 VPN 客户端。
4. VPN 客户端兑换一次性票据并建立会话，继续使用该组的网络访问策略。

登录事务有时效，服务重启、过期或重复兑换后应从 VPN 客户端重新发起，不重放旧回调 URL。SSO 事务保存在单个服务进程；多副本部署须保证整个认证流程到达同一实例，不能据此假定已实现分布式 SSO 会话。

登录事务最长 5 分钟，网页完成后票据最长 60 秒且只可兑换一次。进程最多保留 256 个待完成事务，同一 VPN 源 IP 最多 16 个；大量用户共享 NAT 时应错开集中登录，并在入口配套流量控制。这些上限用于约束内存和简单滥用，不替代网关的抗拒绝服务措施。客户端初始握手的 SSO 能力通过独立短期安全 Cookie 保存，以兼容后续报文不再发送 capabilities 的客户端；该 Cookie 不授予 VPN 访问权限。

| 现象 | 排查方向 |
| --- | --- |
| 没有弹出网页或客户端报告不支持 | 所选组是否 SSO、客户端申报的能力、浏览器模式、外部 SSO 组件 |
| IdP 报 redirect URI 无效 | 精确比较协议、域名、端口、大小写和 `/+CSCOE+/sso/callback` 路径 |
| discovery / JWKS / token 请求失败 | Issuer、端点可达性、TLS 信任、Client ID/Secret 和 IdP 客户端授权 |
| 登录 IdP 成功但 VPN 拒绝 | 映射是否使用真实 sub/稳定ID，AnyLink 用户状态、有效期和组成员资格 |
| 外部页面无法交回客户端 | 客户端是否运行本地回调组件、本机端口占用、代理/浏览器限制，或客户端缺少对应加密能力 |
| 回调提示事务无效 | 超时、重复操作、浏览器 Cookie 被拦截、重启或多实例请求落到不同进程 |

代理和应用日志不得记录完整 callback URL、授权码、票据、Client Secret 或 IdP token。排障使用脱敏错误和事务时间，不分享包含凭据的 HTTP 抓包。

## 验收范围

本次开发已在 Linux 容器中通过以下自动检查，前端产物也已嵌入服务端完成构建：

```sh
# server 目录，Go 1.24
go test -mod=readonly -race ./...
go vet -mod=readonly ./...
go build -mod=readonly -trimpath .
# web 目录
yarn lint --no-fix src/pages/group/List.vue
yarn build
```

测试涵盖受信 TLS 模拟 OIDC/OAuth2 提供方、JWKS/签名/nonce/PKCE、独立 ECIES 解密向量、完整浏览器回调与 VPN 票据兑换、跨会话/跨组重放、账号与组授权复验、并发单次消费、过期与资源上限，以及旧证书/OTP/企微会话不能绕过新 SSO 组策略。没有在真实 IdP、Cisco 客户端或五种操作系统实机上完成登录和隧道测试。

代码和自动化测试提供验证基础，但模拟 IdP 与协议测试不等于实际 AnyConnect GUI 互通。真实 IdP 注册、MFA、客户端弹窗、浏览器回调和 VPN 隧道建立必须在目标环境完成验收，并记录构建版本。

- 正确身份登录后能建立 VPN；未映射、停用、过期或不属于组的账号不能登录。
- 错误/缺失/重放的 state、nonce、PKCE、VPN 票据和跨会话/跨组票据均被拒绝。
- 错误签名、issuer、audience、过期 ID token 和错误 Client Secret 被拒绝。
- 登录取消、超时、刷新回调页面、服务重启后能够通过重新发起登录恢复。
- 分别验收内置与系统浏览器，包括实际 IdP 的 MFA/passkey，确认凭据不进入应用和代理日志。
- 回归原有本地、LDAP、RADIUS 等认证组，验证新 SSO 组的 ACL 和路由限制。
- 在目标操作系统和实际 AnyConnect/Secure Client 版本验证断线重连、客户端升级和必要的证书更新。

身份验证与安全流程依据：[OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)、[OAuth 2.0 安全 BCP](https://www.rfc-editor.org/rfc/rfc9700.html)、[PKCE](https://www.rfc-editor.org/rfc/rfc7636.html)。

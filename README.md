<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
  <img alt="certus 统一认证中心" src="docs/assets/logo-light.svg" width="280">
</picture>

# Certus

Certus 是使用 Go 开发的统一认证中心，面向账号、单点登录、OAuth 2.1、OpenID Connect、令牌和权限管理场景。

适用场景判断与协议详解见 [docs/auth-center-guide.md](docs/auth-center-guide.md)。

## 当前能力

- 可优雅关闭的 HTTP 服务
- 环境变量配置与结构化日志
- 区分存活与依赖就绪的健康检查、请求 ID 和基础安全响应头
- 账号密码登录、Argon2id 凭据、失败锁定和安全 Cookie 会话
- 登录页与认证后的中间落地页
- 接入系统完整生命周期、一次性密钥展示、接入参数生成与软归档
- 动态管理 LDAP/OIDC 身份源，并按接入系统绑定和展示允许的登录方式
- LDAP TLS/StartTLS 登录、外部身份自动映射、最近登录信息与安全解绑
- 外部 OIDC Discovery、授权码 + PKCE、state/nonce 校验与账号自动建档
- OAuth 2.0/2.1 授权码 + PKCE、访问令牌、刷新令牌轮换和客户端凭据
- OAuth/OIDC 用户授权同意、Scope 扩权确认、持久授权复用与用户自助撤销
- RFC 7662 Token Introspection 与 RFC 7009 访问/刷新令牌撤销
- OAuth 令牌与登录会话、用户状态和授权记录联动撤销
- OpenID Connect Discovery、RS256 ID Token、持久化签名密钥、JWKS、UserInfo、重新认证、RP-Initiated Logout 与 Back-Channel Logout
- OAuth 设备授权码、浏览器确认和标准轮询错误
- CAS 1.0/2.0/3.0 Service Ticket 校验、PGT/PT 代理认证、Gateway、Renew 和后端单点登出
- 可选 PostgreSQL 连接池与内嵌、带校验和的自动迁移
- PostgreSQL 全协议仓储；未配置数据库时自动使用开发内存仓储
- 登录、MFA、OAuth 和设备码的统一限流；PostgreSQL 模式支持多实例共享
- 按客户端隔离的角色、权限点、临时授权与 `roles` scope 声明下发
- 协议闭环端到端测试

## 本地运行

```bash
go run ./cmd/certus
```

打开 <http://localhost:8080>。`/healthz` 只反映进程存活，`/readyz` 会在 2 秒内检查 PostgreSQL 等必要依赖；依赖不可用时返回 `503`，可直接用于容器存活与就绪探针。

当前示例客户端为 `specus`，只读接口如下：

```text
GET /api/v1/clients
GET /api/v1/clients/specus
```

有效授权请求会在校验后进入对应客户端的登录页：

```text
GET /oauth2/authorize
    ?client_id=specus
    &redirect_uri=http://localhost:3000/callback
    &response_type=code
    &scope=openid
    &state=<不可预测值>
    &code_challenge=<PKCE挑战值>
    &code_challenge_method=S256
```

## PostgreSQL

设置连接地址后，Certus 会在启动时检查连接、自动执行数据库迁移，并切换到 PostgreSQL 客户端仓储：

```powershell
$env:CERTUS_DATABASE_URL='postgres://certus:certus@localhost:5432/certus?sslmode=disable'
$env:CERTUS_SECRET_ENCRYPTION_KEYS='2026-07=<Base64 编码的 32 字节随机值>'
go run ./cmd/certus
```

生产环境使用 PostgreSQL 时必须配置 `CERTUS_SECRET_ENCRYPTION_KEYS`。不设置 `CERTUS_DATABASE_URL` 时仍使用内存中的 `specus` 示例客户端，方便直接开发。数据库模式不会自动插入示例数据。

首个 migration 已包含：

- OAuth 客户端、精确回调地址和登录方式
- 用户、密码凭据和外部身份映射
- 登录会话
- OAuth 授权码和支持轮换检测的刷新令牌族
- 审计事件

增量 migration 还包含访问令牌、设备授权、CAS Service Ticket / 服务会话、CAS PGT/PT、OIDC 持久化签名密钥、OAuth 用户授权记录、用户令牌的登录会话关联、管理员角色授权、动态身份源、客户端身份源绑定及外部身份管理。升级到会话关联迁移时会撤销无法安全回填会话标识的历史用户令牌，客户端凭据令牌不受影响。

迁移文件已嵌入可执行文件，并在 `certus_schema_migrations` 中记录版本与 SHA-256 校验和；已执行的 migration 被修改时，服务会拒绝启动。

### 升级与回滚

生产升级前应备份 PostgreSQL，并确保所有实例都已配置当前及历史密钥环项。迁移在事务中执行，并通过 PostgreSQL advisory lock 保证多实例只应用一次；可以滚动启动新版本，但应先观察首个实例完成迁移和密钥重封装，再继续替换其余实例。

Certus 不自动执行向下迁移。出现应用层问题时可回滚到仍兼容当前数据库结构的旧二进制；若升级包含不可逆的数据语义变化，应从升级前备份恢复到独立数据库后再切换流量。不要修改已经发布并执行过的 migration，应始终新增后续 migration。

## 统一用户管理

用户主档由 Certus 统一维护，业务系统只消费认证结果和用户标识。当前支持：

- 用户名和邮箱唯一性约束
- 用户名、显示名称和邮箱搜索
- 分页与状态筛选
- `active`、`locked`、`disabled` 生命周期状态
- 更新显示名称、邮箱和状态
- 内存与 PostgreSQL 两种仓储

后台使用 Certus 用户身份、独立管理员 RBAC 和强制 MFA。管理员必须先以普通用户身份启用 TOTP，再通过包含 `otp` 的 AAL2 会话访问 `/admin`。内置角色：

- `super_admin`：全部权限及管理员角色分配
- `identity_admin`：用户、密码、会话和 MFA
- `application_admin`：接入系统及业务角色权限
- `security_admin`：签名密钥、数据清理与安全审计
- `auditor`：用户、客户端、安全状态与审计日志只读访问

首次引导或应急自动化可临时配置至少 32 个字符的高熵 Bearer Token：

```powershell
$env:CERTUS_ADMIN_TOKEN='<至少 32 个字符的随机密钥>'
go run ./cmd/certus
```

应急令牌拥有超级管理员权限，但不用于浏览器控制台；完成首位 `super_admin` 授权后可从运行环境移除。通过应急令牌分配首位管理员：

```http
PUT /api/v1/admin/users/{user_id}/admin-roles
Authorization: Bearer <CERTUS_ADMIN_TOKEN>
Content-Type: application/json

{"roles":["super_admin"]}
```

服务端禁止移除最后一个 `super_admin`。管理员角色在每次请求时动态计算，权限收回立即生效。管理员会话的写请求还必须同时携带页面签发的 CSRF Cookie 与 `X-CSRF-Token` 请求头；应急 Bearer Token 不依赖浏览器 Cookie。

管理 API：

```text
GET  /api/v1/admin/me
GET  /api/v1/admin/roles
GET  /api/v1/admin/users?q=&status=&limit=20&offset=0
POST /api/v1/admin/users
POST /api/v1/admin/users/import
GET  /api/v1/admin/users/{user_id}
PUT  /api/v1/admin/users/{user_id}
PUT  /api/v1/admin/users/{user_id}/password
POST /api/v1/admin/users/{user_id}/password-reset
GET  /api/v1/admin/users/{user_id}/external-identities
DELETE /api/v1/admin/users/{user_id}/external-identities/{external_identity_id}
GET  /api/v1/admin/users/{user_id}/sessions
DELETE /api/v1/admin/users/{user_id}/sessions
DELETE /api/v1/admin/users/{user_id}/sessions/{session_id}
DELETE /api/v1/admin/users/{user_id}/mfa
GET  /api/v1/admin/users/{user_id}/admin-roles
PUT  /api/v1/admin/users/{user_id}/admin-roles
GET  /api/v1/admin/audit-events
GET  /api/v1/admin/signing-keys
POST /api/v1/admin/signing-keys/rotate
POST /api/v1/admin/maintenance/cleanup
POST /api/v1/admin/email/test
```

外部身份列表只返回管理所需的来源、Subject、安全化资料和最近登录时间，不返回上游令牌或原始 Claims。解除绑定会撤销该用户的全部登录会话和 OAuth 令牌；若用户既没有密码也没有其他外部身份，接口返回 `409 last_authentication_method`，防止账号失去所有登录方式。

创建用户：

```json
{
  "username": "alice",
  "display_name": "Alice",
  "email": "alice@example.com",
  "status": "active"
}
```

更新采用完整替换语义，用户名保持不可变；将状态改为 `disabled` 代替物理删除，以保留历史授权与审计引用。

密码通过独立端点设置：

```json
{
  "password": "至少 12 个字符的新密码"
}
```

服务端对新设置和新注册的密码只保存 Argon2id 哈希；连续失败 5 次会锁定凭据 15 分钟。唯一例外是下面带明确来源与到期时间的旧系统渐进迁移凭据。

### 已有系统密码迁移

Certus 支持把 Specus 现有用户及其旧密码摘要整批导入，然后在用户第一次成功登录时透明升级。Specus 的原格式是无盐的 `hex(SHA-256(UTF-8(password)))`；Certus 只在管理员明确声明 `specus_sha256` 时接受该格式，存储时会同时封装来源和到期时间，不会把普通 64 位字符串自动识别为旧密码。

`POST /api/v1/admin/users/import` 需要 `admin.users.write` 权限，一次接受 1–1000 个用户：

```json
{
  "password_algorithm": "specus_sha256",
  "expires_at": "2026-10-29T00:00:00Z",
  "users": [
    {
      "username": "alice",
      "display_name": "Alice",
      "email": "alice@example.com",
      "status": "active",
      "password_hash": "Specus 数据库中的 64 位小写 SHA-256 摘要"
    }
  ]
}
```

`expires_at` 可省略，默认自导入起 90 天，最长不能超过 365 天。整批写入使用同一个事务；任意用户名、邮箱或输入冲突都会回滚全部用户，并且绝不覆盖 Certus 已有账号或密码。响应只返回创建的用户、数量和到期时间，不回显摘要。

迁移期间用户仍输入原 Specus 密码。Certus 使用固定时间比较验证旧摘要，首次成功后在同一次登录中写入新的 Argon2id 摘要并清除旧摘要；如果升级写入失败则拒绝登录，不会带着弱摘要降级放行。到期前未完成首次登录的账号需要走密码重置。完成迁移后应关闭 Specus 本地密码登录，并安全删除导出文件。

管理员密码重置接口返回一个仅显示一次、30 分钟有效的 `reset_token`，交付通道由部署方接入邮件或工单系统。账号自助接口使用当前登录会话：

```text
GET    /account
GET    /api/v1/account/profile
GET    /api/v1/account/sessions
DELETE /api/v1/account/sessions/{session_id}
GET    /api/v1/account/consents
DELETE /api/v1/account/consents/{client_id}
PUT    /api/v1/account/password
POST   /api/v1/account/password/reset
```

`/account` 提供登录用户自助安全中心，可查看身份资料、活跃会话、已授权应用、修改密码及配置 MFA；未登录访问会先完成认证再返回。撤销应用授权会在同一事务中撤销该用户与客户端之间的授权码、访问令牌、刷新令牌和未兑换设备授权；该客户端下次交互式授权必须重新取得同意。用户改密必须提交 `current_password` 与 `new_password`，成功后保留当前会话并撤销其他会话及其令牌；一次性重置成功后撤销全部会话和用户令牌。本地退出表单也必须携带页面签发的 CSRF Token。审计接口支持 `actor_user_id`、`event_type`、`client_id`、`outcome`、`from`、`to` 与分页筛选。

### TOTP 多因素认证

生产环境使用版本化密钥环对每个用户独立生成的 TOTP 密钥执行 AES-256-GCM 封装。密钥环首项是新写入使用的主密钥，其余项只用于解密和无停机轮换：

```powershell
$env:CERTUS_SECRET_ENCRYPTION_KEYS='2026-08=<当前Base64-32字节>,2026-07=<旧Base64-32字节>'
```

早期版本的 `CERTUS_MFA_ENCRYPTION_KEY` 仅作为旧 TOTP 密文的迁移密钥保留。升级时应同时配置它和新的密钥环；Certus 启动后会把旧密文原子重封装到密钥环首项。确认所有实例均完成启动后即可移除旧变量。全新部署不需要配置该旧变量。

账号安全 API：

```text
GET    /api/v1/account/mfa
POST   /api/v1/account/mfa/totp/setup
POST   /api/v1/account/mfa/totp/enable
POST   /api/v1/account/mfa/recovery-codes
DELETE /api/v1/account/mfa/totp
```

`GET` 响应中的 `csrf_token` 必须通过 `X-CSRF-Token` 请求头传给所有账号安全写接口，并同时携带登录会话 Cookie。注册 TOTP 前还会重新验证当前密码；`setup` 返回 `otpauth_uri`、Base32 密钥、用于本地 SVG 渲染的 `qr_code_rows` 和 10 枚仅显示一次的高熵恢复码。账户安全页会直接展示可供认证器扫描的二维码，不依赖外部图片或二维码服务。恢复码重新生成同时要求当前密码和一个有效的动态口令或现有恢复码，成功后在同一事务中废止全部旧码并返回 10 枚只显示一次的新码。

TOTP 使用 RFC 6238 的 30 秒时间步与 HMAC-SHA-1 兼容模式，允许前后各一个时间步的时钟偏差。服务端原子记录最后成功时间步，拒绝同一动态口令重放；恢复码仅存 SHA-256 哈希且成功后立即作废。启用 MFA 的账号在密码、LDAP 或外部 OIDC 主认证后都必须完成第二步验证；若所需密钥版本缺失或密文无法解密，Certus 会拒绝降级登录。OIDC ID Token 同时下发 `amr` 与 `acr`（`urn:certus:aal:1` / `urn:certus:aal:2`）。

### LDAP 与外部 OIDC

推荐在管理控制台的“身份源”中创建 LDAP 或 OIDC 配置，再通过客户端的 `identity_source_ids` 显式绑定允许使用的来源。身份源凭据使用 `CERTUS_SECRET_ENCRYPTION_KEYS` 封装，读取管理接口时只返回 `secret_configured`，不会返回明文。管理 API：

```text
GET    /api/v1/admin/identity-sources
POST   /api/v1/admin/identity-sources
GET    /api/v1/admin/identity-sources/{source_id}
PUT    /api/v1/admin/identity-sources/{source_id}
DELETE /api/v1/admin/identity-sources/{source_id}
POST   /api/v1/admin/identity-sources/{source_id}/probe
```

探测操作使用 6 秒请求期限，OIDC HTTP 客户端不跟随重定向；OIDC Issuer 必须使用 HTTPS（本机回环开发地址除外），LDAP 可使用 LDAPS 或 StartTLS。已绑定到未归档客户端的身份源不能归档；应先解除所有客户端绑定。

环境变量形式的全局 LDAP/OIDC 配置仍作为兼容入口，仅供没有设置 `identity_source_ids` 的客户端使用。LDAP 支持服务账号搜索后以最终用户 DN 绑定：

```powershell
$env:CERTUS_LDAP_URL='ldaps://ldap.example.com:636'
$env:CERTUS_LDAP_BASE_DN='ou=people,dc=example,dc=com'
$env:CERTUS_LDAP_BIND_DN='cn=certus,ou=services,dc=example,dc=com'
$env:CERTUS_LDAP_BIND_PASSWORD='<LDAP 服务账号密码>'
$env:CERTUS_LDAP_USER_FILTER='(&(objectClass=person)(uid={username}))'
```

使用 `ldap://` 时可通过 `CERTUS_LDAP_START_TLS=true` 强制升级到 TLS。用户输入会在代入过滤器前转义，空密码不会发送到 LDAP。

外部 OIDC 使用发现文档、授权码和 PKCE：

```powershell
$env:CERTUS_EXTERNAL_OIDC_ISSUER='https://idp.example.com'
$env:CERTUS_EXTERNAL_OIDC_CLIENT_ID='certus'
$env:CERTUS_EXTERNAL_OIDC_CLIENT_SECRET='<OIDC 客户端密钥>'
$env:CERTUS_EXTERNAL_OIDC_LABEL='企业统一身份'
```

在上游登记的回调地址固定为 `${CERTUS_ISSUER}/login/oidc/callback`。只有上游标记为已验证的邮箱才用于关联现有 Certus 用户；否则会创建独立用户，避免仅凭未验证邮箱合并账号。

## 配置跳转登录系统

管理员可以登记需要跳转到 Certus 登录的业务系统：

```text
GET  /admin
GET  /admin/clients
GET  /api/v1/admin/clients
POST /api/v1/admin/clients
GET  /api/v1/admin/clients/{client_id}
PUT  /api/v1/admin/clients/{client_id}
DELETE /api/v1/admin/clients/{client_id}
POST /api/v1/admin/clients/{client_id}/secret
GET  /api/v1/admin/clients/{client_id}/integration
```

`/admin` 是统一管理控制台，覆盖用户生命周期、管理员角色、密码与会话处置、MFA 重置、接入系统、业务角色权限、审计日志、OIDC 签名密钥和过期数据清理。`/admin/clients` 保留为兼容入口并展示同一控制台。未登录访问会跳转到统一登录；没有管理员角色的用户会被拒绝，未达到 AAL2 的管理员会被引导完成 MFA 或重新登录。后台不再把全局管理员令牌保存到浏览器。

创建配置：

```json
{
  "id": "finance",
  "name": "Finance",
  "description": "财务系统",
  "launch_uri": "https://finance.example.com/?login=oidc",
  "application_type": "confidential",
  "token_endpoint_auth_method": "client_secret_basic",
  "protocols": [
    "oauth2.0",
    "oauth2.1",
    "cas"
  ],
  "grant_types": [
    "authorization_code",
    "refresh_token",
    "client_credentials"
  ],
  "redirect_uris": [
    "https://finance.example.com/oidc/callback"
  ],
  "post_logout_redirect_uris": [
    "https://finance.example.com/logout/callback"
  ],
  "backchannel_logout_uri": "https://finance.example.com/oidc/backchannel-logout",
  "backchannel_logout_session_required": true,
  "login_methods": [
    "password",
    "ldap"
  ],
  "identity_source_ids": [
    "workforce"
  ],
  "introspectable_by": [
    "resource-api"
  ],
  "allowed_scopes": [
    "openid",
    "profile",
    "email"
  ],
  "cas_version": "3.0",
  "cas_service_urls": [
    "https://finance.example.com/login/cas"
  ],
  "cas_proxy": true,
  "cas_gateway": true,
  "cas_renew": false,
  "cas_single_logout": true
}
```

`launch_uri` 是 `/portal` 中系统按钮使用的业务入口；它必须先在业务系统侧创建 `state`、`nonce` 与 PKCE verifier，再进入 Certus 授权端点。OAuth/OIDC 客户端不要把回调地址直接当作启动地址。

创建成功后响应会同时给出业务系统所需的接入参数：

```json
{
  "integration": {
    "supported_protocols": [
      "oauth2.0",
      "oauth2.1",
      "cas"
    ],
    "issuer": "https://auth.example.com",
    "discovery_url": "https://auth.example.com/.well-known/openid-configuration",
    "client_id": "finance",
    "launch_uri": "https://finance.example.com/?login=oidc",
    "client_secret": "<仅本次响应显示>",
    "client_authentication_method": "client_secret_basic",
    "authorization_endpoint": "https://auth.example.com/oauth2/authorize",
    "token_endpoint": "https://auth.example.com/oauth2/token",
    "introspection_endpoint": "https://auth.example.com/oauth2/introspect",
    "revocation_endpoint": "https://auth.example.com/oauth2/revoke",
    "userinfo_endpoint": "https://auth.example.com/oauth2/userinfo",
    "end_session_endpoint": "https://auth.example.com/oauth2/logout",
    "jwks_uri": "https://auth.example.com/oauth2/jwks",
    "redirect_uris": [
      "https://finance.example.com/oidc/callback"
    ],
    "post_logout_redirect_uris": [
      "https://finance.example.com/logout/callback"
    ],
    "backchannel_logout_uri": "https://finance.example.com/oidc/backchannel-logout",
    "backchannel_logout_session_required": true,
    "scopes": [
      "openid",
      "profile",
      "email"
    ],
    "response_types": [
      "code"
    ],
    "grant_types": [
      "authorization_code",
      "refresh_token",
      "client_credentials"
    ],
    "pkce": {
      "required": true,
      "challenge_method": "S256"
    },
    "cas": {
      "version": "3.0",
      "service_urls": [
        "https://finance.example.com/login/cas"
      ],
      "login_url": "https://auth.example.com/cas/login",
      "logout_url": "https://auth.example.com/cas/logout",
      "validate_url": "https://auth.example.com/cas/p3/serviceValidate",
      "proxy_validate_url": "https://auth.example.com/cas/p3/proxyValidate",
      "proxy_url": "https://auth.example.com/cas/proxy",
      "gateway": true,
      "renew": false,
      "single_logout": true
    }
  }
}
```

`public` 客户端固定使用 `none` 且不生成密钥；`confidential` 客户端可选择 `client_secret_basic`（默认、推荐）或 `client_secret_post`。所选方式会统一应用于 Token、Device Authorization、Introspection 和 Revocation 端点；同一请求同时提交 Basic 与表单密钥会被拒绝。机密客户端的明文密钥只在创建或轮换响应中出现一次，Certus 只保存 SHA-256 哈希。非本机回环地址的回调必须使用 HTTPS，回调地址在授权时执行精确匹配。

`identity_source_ids` 中的身份源必须存在、启用、未归档，且类型必须与 `login_methods` 中的 `ldap` / `oidc` 对应。配置显式绑定后，登录页和协议回调都只接受这些来源，不能通过构造请求绕过客户端限制。

`introspectable_by` 由令牌签发客户端配置，成员必须是存在、启用、未归档的 `confidential` OAuth 客户端。默认空数组会拒绝所有跨客户端内省；配置后仅允许列出的资源服务器内省该客户端签发的 Access Token，并继续按原客户端校验用户、会话、授权同意、Scope、角色与权限。Refresh Token 始终只允许签发它的机密客户端内省，不通过该白名单开放。白名单使用完整 `client_id` 精确匹配，不支持通配符或前缀。

`PUT` 采用完整替换语义，但 `client_id` 和客户端类型保持不可变；通过 `enabled:false` 可停止新登录，并立即撤销该客户端的授权码、访问令牌、刷新令牌和待处理设备授权。`POST .../secret` 立即轮换机密客户端的密钥，新明文同样只显示一次。`DELETE` 执行软归档并同时禁用客户端；历史令牌和授权记录不会物理删除，但令牌会被标记为已撤销，审计引用得以保留。

## 角色与权限下发

角色和权限点始终按 `client_id` 隔离，用户可被授予带过期时间的临时角色。管理接口如下：

```text
GET  /api/v1/admin/clients/{client_id}/roles
POST /api/v1/admin/clients/{client_id}/roles
GET  /api/v1/admin/clients/{client_id}/roles/{role_id}
PUT  /api/v1/admin/clients/{client_id}/roles/{role_id}
DELETE /api/v1/admin/clients/{client_id}/roles/{role_id}
GET  /api/v1/admin/clients/{client_id}/permissions
POST /api/v1/admin/clients/{client_id}/permissions
GET  /api/v1/admin/clients/{client_id}/permissions/{permission_id}
PUT  /api/v1/admin/clients/{client_id}/permissions/{permission_id}
DELETE /api/v1/admin/clients/{client_id}/permissions/{permission_id}
GET  /api/v1/admin/clients/{client_id}/roles/{role_id}/permissions
PUT  /api/v1/admin/clients/{client_id}/roles/{role_id}/permissions
GET  /api/v1/admin/users/{user_id}/roles?client_id=
PUT  /api/v1/admin/users/{user_id}/roles
```

角色和权限点的 `PUT` 都采用完整替换语义。为避免误操作静默改变线上授权，仍分配给任一用户（包括已过期分配）的角色不能删除，仍被任一角色引用的权限点也不能删除；接口返回 `409 Conflict`，管理员解除对应分配或映射后才能继续。角色、权限点、权限映射及用户角色的变更会写入细粒度审计事件。

角色授予采用完整替换语义：

```json
{
  "roles": [
    {
      "role_id": "角色 UUID",
      "expires_at": "2026-12-31T16:00:00Z"
    }
  ]
}
```

客户端必须在 `allowed_scopes` 中显式加入并请求 `roles`，Certus 才会在 ID Token、UserInfo 和 Introspection 中下发当前客户端范围内的 `roles` 与 `permissions`。CAS 3.0 客户端在 `allowed_scopes` 包含 `roles` 时，会获得对应的 `<cas:role>` 与 `<cas:permission>` 属性。机密客户端也可使用 Basic 认证实时查询：

```text
GET /api/v1/access/users/{user_id}
```

令牌中的授权声明是签发时快照；高敏感操作可使用实时查询或 Introspection 缩短权限撤销的生效时延。

### 支持方式

- OAuth 2.0：授权码 + PKCE、刷新令牌、客户端凭据、设备码
- OAuth 2.1：授权码 + PKCE、刷新令牌、客户端凭据、设备码
- OAuth 客户端认证：`none`、`client_secret_basic`、`client_secret_post`
- OAuth 令牌管理：受客户端认证保护、支持显式资源服务器白名单的 Introspection 与幂等 Revocation
- OpenID Connect：通过 `openid` scope 为 OAuth 登录提供用户身份
- CAS 1.0、2.0、3.0：Service Ticket 校验参数
- CAS 2.0/3.0：代理认证
- CAS：Gateway、Renew 和单点登出选项

OAuth 2.1 当前仍是 IETF Internet-Draft。出于安全原因，Certus 不开放 OAuth implicit 和 resource owner password grant；OAuth Security BCP 已明确不应使用这些遗留流程。

OIDC 授权请求支持 `prompt=none`、`prompt=login`、`prompt=consent` 与非负整数 `max_age`。首次授权、请求新增 Scope 或显式使用 `prompt=consent` 时，Certus 会展示客户端与权限范围并记录用户决定；已有授权覆盖全部 Scope 时可直接复用。静默认证无法完成时，Certus 会将 `login_required` 或 `consent_required` 和原始 `state` 返回到已登记的精确回调地址；强制重新认证与授权同意都使用 5 分钟有效、绑定完整授权请求且完成后即失效的签名事务。授权码签发记录认证时间，后续 ID Token 始终携带 `auth_time`。

授予 `email` scope 且用户存在邮箱时，ID Token 与 UserInfo 会同时返回 `email` 和布尔型 `email_verified`。本地注册、管理员录入、密码导入及 LDAP 邮箱默认未验证；仅当上游 OIDC 明确声明 `email_verified=true` 且邮箱与当前用户邮箱一致时继承验证状态，邮箱变更会自动重置该状态。

刷新令牌支持可选 `scope` 缩减，不允许恢复已经缩减或原始授权未包含的范围。每次刷新、UserInfo 与 Introspection 都重新检查用户状态、登录会话和当前授权；用户退出、会话撤销、用户禁用、密码重置、管理员 MFA 重置或应用授权撤销后，不再签发或接受关联令牌。

资源服务器使用自己的机密客户端凭据调用 Introspection。令牌签发客户端可通过 `introspectable_by` 显式授权资源服务器读取 Access Token 状态；未授权、目标已停用或令牌不可用时统一返回 `{"active":false}`，不泄露令牌是否存在及拒绝原因。该配置的管理 API 变更由统一后台审计记录。

OIDC 客户端可将 ID Token 作为 `id_token_hint` 请求 `GET` 或 `POST /oauth2/logout`。Certus 验证签名、发行者、受众及当前用户后撤销对应统一会话和 OAuth 令牌；仅当 `post_logout_redirect_uri` 与客户端独立登记的退出回调完全一致时才携带可选 `state` 跳回业务系统。

配置 `backchannel_logout_uri` 后，Certus 会记录每个统一会话访问过的 OIDC 客户端。用户退出、RP-Initiated Logout、账户或管理员撤销会话、改密/重置密码以及管理员重置 MFA 时，服务端会向相关客户端并行 POST 带签名 `logout+jwt` 的 `logout_token`。令牌包含 `iss`、`sub`、`aud`、`iat`、`exp`、`jti`、`sid` 与标准退出 `events`，不包含 `nonce`；单次注销投递共用 5 秒超时且不跟随重定向。

## 用户自助注册

自助注册默认关闭。启用后，账号密码登录页会显示“创建 Certus 账号”，也可直接访问 `GET /register`。从 OAuth、CAS 或设备登录流程进入时，注册页会校验目标客户端是否允许账号密码登录；成功创建账号和 Argon2id 密码凭据后立即建立统一会话，并返回注册前的协议流程。用户与密码在 PostgreSQL 中通过同一事务写入，不会留下只有用户、没有密码的半成品账号。

```powershell
$env:CERTUS_REGISTRATION_ENABLED='true'
$env:CERTUS_REGISTRATION_REQUIRE_EMAIL='true'
```

邮箱默认必填并执行格式及唯一性校验；设为 `false` 可允许不填写邮箱。当前阶段创建的账号会立即激活，尚未验证邮箱所有权，也没有自动授予任何接入系统角色。公网开放前应结合后续邮箱验证码和人机校验能力；需要访问 Specus 的新用户仍需由管理员授予对应的客户端角色。

生产环境启用注册时，`CERTUS_ISSUER` 必须使用 HTTPS。注册表单使用同源 CSRF 防护，只接受内部允许列表中的继续地址，并默认按来源地址限制每小时 5 次：

```powershell
$env:CERTUS_REGISTRATION_RATE_LIMIT='5'
$env:CERTUS_REGISTRATION_RATE_WINDOW='1h'
```

## SMTP 邮件发送

Certus 支持 465 隐式 TLS 和 587 STARTTLS，最低 TLS 版本为 1.2。SMTP 密码只从运行环境读取，不会出现在 API 响应、审计详情或普通日志中。发件地址和显示名称分别配置，包含中文的显示名称会自动按邮件标准编码：

```powershell
$env:CERTUS_SMTP_HOST='smtp.exmail.qq.com'
$env:CERTUS_SMTP_PORT='465'
$env:CERTUS_SMTP_USERNAME='support@devshuai.com'
$env:CERTUS_SMTP_PASSWORD='<轮换后的 SMTP 授权码或密码>'
$env:CERTUS_SMTP_TLS_MODE='implicit'
$env:CERTUS_EMAIL_FROM_ADDRESS='support@devshuai.com'
$env:CERTUS_EMAIL_FROM_NAME='Certus'
```

`CERTUS_SMTP_TLS_MODE` 只接受 `implicit` 或 `starttls`，不允许明文 SMTP。配置用户名时必须同时配置密码；SMTP 主机存在时必须配置合法发件地址和 1–128 字符的发件名称。

具备 `admin.security.write` 权限并完成管理员 MFA 后，可发送固定内容的测试邮件；应急管理员令牌也可用于部署检查：

```http
POST /api/v1/admin/email/test
Authorization: Bearer <CERTUS_ADMIN_TOKEN>
Content-Type: application/json

{"to":"operator@example.com"}
```

接口不允许调用方自定义主题或正文，避免被滥用为任意邮件转发器。当前 SMTP 层用于连接、认证、标准 MIME 消息构造和测试发送；注册邮箱验证码将在后续注册验证状态机中接入。

## 请求来源与认证限流

Certus 对注册、密码/LDAP 登录、MFA、OAuth 令牌及元数据端点和设备码查询执行固定窗口限流。登录同时按来源地址和规范化账号计数，MFA 同时按来源地址和用户计数；PostgreSQL 模式使用原子更新在多个实例间共享状态，数据库仅保存主体的 SHA-256，不保存用户名或 IP 明文。限流仓储不可用时认证请求会拒绝继续，避免无保护降级。

```powershell
$env:CERTUS_LOGIN_SOURCE_RATE_LIMIT='30'
$env:CERTUS_LOGIN_SOURCE_RATE_WINDOW='1m'
$env:CERTUS_LOGIN_IDENTITY_RATE_LIMIT='10'
$env:CERTUS_LOGIN_IDENTITY_RATE_WINDOW='5m'
$env:CERTUS_REGISTRATION_RATE_LIMIT='5'
$env:CERTUS_REGISTRATION_RATE_WINDOW='1h'
$env:CERTUS_MFA_RATE_LIMIT='10'
$env:CERTUS_MFA_RATE_WINDOW='5m'
$env:CERTUS_OAUTH_RATE_LIMIT='600'
$env:CERTUS_OAUTH_RATE_WINDOW='1m'
$env:CERTUS_DEVICE_RATE_LIMIT='20'
$env:CERTUS_DEVICE_RATE_WINDOW='1m'
```

将对应的 `*_RATE_LIMIT` 设为 `0` 可单独关闭一类限制。每个窗口必须在 1 秒到 24 小时之间；被限制的响应返回 `429`、`Retry-After` 和 `X-RateLimit-*` 元数据。

默认只使用 TCP 直连来源地址并忽略转发头。部署在反向代理后时，应仅登记真实代理的 IP 或 CIDR：

```powershell
$env:CERTUS_TRUSTED_PROXIES='10.0.0.0/8,192.0.2.10'
```

只有直接连接来自上述可信网段时才会解析 `X-Forwarded-For`，并从右向左剥离可信代理；格式异常或链路过长时退回直连地址，防止客户端伪造来源绕过限流或污染审计。

## Prometheus 指标

配置独立的高熵令牌后才会注册 `GET /metrics`；未配置时该路径返回 `404`。指标令牌与管理员应急令牌相互独立：

```powershell
$env:CERTUS_METRICS_TOKEN='<至少 32 个字符的随机值>'
curl.exe -H "Authorization: Bearer $env:CERTUS_METRICS_TOKEN" http://localhost:8080/metrics
```

当前指标覆盖：

- HTTP 请求数、响应字节和固定桶耗时直方图
- 密码、LDAP、OIDC 与 MFA 各认证阶段的成功/失败数
- 各限流作用域的允许、拦截与仓储错误数
- 就绪检查、过期数据清理和签名密钥轮换结果及耗时
- PostgreSQL 连接池总量、占用、空闲、获取次数和获取耗时
- 可执行文件版本和提交信息

HTTP 指标的 `route` 标签来自 Go 路由模板，例如 `GET /api/v1/admin/users/{userID}`，不会使用原始 URL；认证和限流标签也只接受代码内的固定低基数值，不包含用户名、用户 ID、客户端 ID、IP、令牌或密钥。

## Elastic APM

配置 `ELASTIC_APM_SERVER_URL` 后，Certus 会启用 Elastic 官方 Go Agent；也可以显式设置 `ELASTIC_APM_ACTIVE=true` 使用 Agent 的默认地址。未配置这两项时不会初始化 Agent，避免开发环境自动连接 `localhost:8200`。

```bash
ELASTIC_APM_ACTIVE=true
ELASTIC_APM_SERVER_URL=http://apm-server.internal:8200
ELASTIC_APM_ENVIRONMENT=production
ELASTIC_APM_SERVICE_VERSION=1.0.0
ELASTIC_APM_TRANSACTION_SAMPLE_RATE=0.2
ELASTIC_APM_TRANSACTION_MAX_SPANS=200
ELASTIC_APM_CAPTURE_BODY=off
ELASTIC_APM_CAPTURE_HEADERS=false
ELASTIC_APM_CENTRAL_CONFIG=false
ELASTIC_APM_TRANSACTION_IGNORE_URLS=/healthz,/readyz,/metrics,/static/*
CERTUS_APM_SQL_PARAMETERS=detailed
```

接入范围包括：

- HTTP 服务端事务，事务名使用 Go 路由模板，不把用户 ID、客户端 ID 等动态路径写入事务名
- pgx PostgreSQL 查询、批处理、复制和连接 span
- CAS 回调、OIDC 请求、身份源探测及 favicon 抓取等出站 HTTP span
- `slog` 错误事件以及请求访问日志中的 `trace.id`、`transaction.id` 关联字段
- 进程退出前最多等待 5 秒刷新尚未发送的事件

认证服务应保持 `ELASTIC_APM_CAPTURE_BODY=off` 和 `ELASTIC_APM_CAPTURE_HEADERS=false`，避免采集密码、授权码、Cookie 或 Bearer Token。更多采样、认证和传输配置参见 [Elastic APM Go Agent 配置文档](https://www.elastic.co/docs/reference/apm/agents/go/configuration)。

`CERTUS_APM_SQL_PARAMETERS=detailed` 会在 PostgreSQL span 上增加 `db_parameter_count`、`db_parameters_captured` 和 `db_parameter_01` 至 `db_parameter_32` 标签。每个参数包含 Go 类型和值；单个值最多保留 768 个字符，超出时注明原始长度。密码、密钥、令牌、会话、票据、MFA、授权码、私钥、密文、哈希字段以及所有二进制值无条件替换为 `[REDACTED]`，但仍保留类型和长度。此功能默认关闭，因为参数标签会增加 APM 事件体积和索引基数。

## 运维与密钥轮换

PostgreSQL 模式默认启动时执行一次清理，之后每 15 分钟清理过期或已消费的 OAuth、CAS、会话、密码重置及限流数据；审计默认保留 90 天。管理员也可调用 `POST /api/v1/admin/maintenance/cleanup` 立即执行并取得各表删除计数。

```powershell
$env:CERTUS_CLEANUP_INTERVAL='15m'       # 设为 0 关闭定时清理
$env:CERTUS_AUDIT_RETENTION='2160h'      # 90 天
$env:CERTUS_SIGNING_KEY_RETENTION='24h'  # 不得少于 1 小时
$env:CERTUS_SIGNING_KEY_ROTATION_INTERVAL='24h' # 设为 0 关闭，不得少于 1 小时
$env:CERTUS_SECRET_ENCRYPTION_KEYS='2026-07=<Base64-32字节>,2026-06=<旧密钥>'
```

OIDC 私钥、TOTP 密钥和动态身份源凭据都使用 AES-256-GCM 封装后写入 PostgreSQL。密文的附加认证数据绑定用途、记录标识和主密钥版本，避免跨用途或跨记录替换。服务启动时会把历史明文 OIDC 私钥、旧版 TOTP 密文、身份源凭据及旧主密钥密文自动重封装到密钥环首项；升级已有数据库时应先同时配置新旧主密钥及所需的旧版 MFA 密钥，确认所有实例完成启动迁移后再移除旧项。

服务默认每 24 小时检查并轮换活动 RS256 密钥，多实例通过 PostgreSQL 事务锁保证只产生一个新活动密钥。`POST /api/v1/admin/signing-keys/rotate` 仍可立即手动轮换；`GET /api/v1/admin/signing-keys` 只返回元数据，不返回私钥。退役公钥在保留期内继续发布到 JWKS，用于验证尚未过期的 ID Token 和登录事务。多实例每 30 秒自动收敛到数据库中的活动密钥；保留期应长于系统允许的最长签名令牌寿命与 JWKS 缓存时间之和。

## 构建与发布

[`.github/workflows/release.yml`](.github/workflows/release.yml) 支持两种触发方式：

- 在 GitHub Actions 页面使用 `workflow_dispatch` 手动执行，可指定版本并选择是否推送镜像。
- 向 `release` 分支提交代码时自动执行。

每次运行都会先在独立 PostgreSQL 服务和随机测试 schema 中执行真实迁移/仓储集成测试及静态检查，然后生成以下服务端包：

```text
Linux   amd64 / arm64
Windows amd64 / arm64
macOS   amd64 / arm64
```

各平台压缩包、可直接在下载目录校验的独立 SHA-256 文件和总 `SHA256SUMS` 会保存为 GitHub Actions artifacts。二进制支持查看构建信息：

```bash
certus --version
```

Docker 使用 [`Dockerfile`](Dockerfile) 构建 `linux/amd64` 和 `linux/arm64` 多架构镜像并推送到：

```text
ghcr.io/devshuai/certus
```

`release` 分支构建会产生 `release`、`release-<commit>` 和 `sha-<commit>` 标签；手动构建使用输入的版本标签。镜像以无 root、无 shell 的最小运行环境启动：

```bash
docker run --rm -p 8080:8080 \
  -e CERTUS_DATABASE_URL='postgres://certus:password@postgres:5432/certus' \
  -e CERTUS_ADMIN_TOKEN='<至少 32 个字符的随机密钥>' \
  -e CERTUS_SECRET_ENCRYPTION_KEYS='primary=<Base64 编码的 32 字节随机值>' \
  ghcr.io/devshuai/certus:release
```

手动运行若关闭“推送镜像”，工作流仍会生成包含 `linux/amd64` 与 `linux/arm64` manifest 的 `certus-container-image` OCI 归档及校验文件；可使用支持 OCI layout 的容器工具导入或复制。所有发布任务都配置了有限超时，异常构建不会无限占用执行器。

## 模块边界

```text
cmd/certus                 服务入口
internal/config            配置
internal/platform/http     HTTP 路由与中间件
internal/identity          用户、凭据与外部身份源
internal/oauth             OAuth 2.1 / OIDC 协议
internal/client            接入系统及登录方式配置
internal/access            角色、权限与访问策略
internal/session           登录会话
internal/audit             审计事件
internal/mfa               TOTP 与恢复码
internal/maintenance       数据保留与清理
web                        登录页和中间落地页
```

协议执行数据默认持久化到 PostgreSQL；未设置数据库地址时使用仅供开发和测试的内存实现。

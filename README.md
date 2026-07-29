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
- 健康检查、请求 ID 和基础安全响应头
- 账号密码登录、Argon2id 凭据、失败锁定和安全 Cookie 会话
- 登录页与认证后的中间落地页
- 接入系统领域模型、内存仓储与只读查询 API
- 按接入系统动态展示账号密码、LDAP 和外部 OIDC 登录方式
- LDAP TLS/StartTLS 登录与外部身份自动映射
- 外部 OIDC Discovery、授权码 + PKCE、state/nonce 校验与账号自动建档
- OAuth 2.0/2.1 授权码 + PKCE、访问令牌、刷新令牌轮换和客户端凭据
- RFC 7662 Token Introspection 与 RFC 7009 访问/刷新令牌撤销
- OpenID Connect Discovery、RS256 ID Token、持久化签名密钥、JWKS 和 UserInfo
- OAuth 设备授权码、浏览器确认和标准轮询错误
- CAS 1.0/2.0/3.0 Service Ticket 校验、PGT/PT 代理认证、Gateway、Renew 和后端单点登出
- 可选 PostgreSQL 连接池与内嵌、带校验和的自动迁移
- PostgreSQL 全协议仓储；未配置数据库时自动使用开发内存仓储
- 按客户端隔离的角色、权限点、临时授权与 `roles` scope 声明下发
- 协议闭环端到端测试

## 本地运行

```bash
go run ./cmd/certus
```

打开 <http://localhost:8080>。健康检查位于 <http://localhost:8080/healthz>。

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
go run ./cmd/certus
```

不设置 `CERTUS_DATABASE_URL` 时仍使用内存中的 `specus` 示例客户端，方便直接开发。数据库模式不会自动插入示例数据。

首个 migration 已包含：

- OAuth 客户端、精确回调地址和登录方式
- 用户、密码凭据和外部身份映射
- 登录会话
- OAuth 授权码和支持轮换检测的刷新令牌族
- 审计事件

增量 migration 还包含访问令牌、设备授权、CAS Service Ticket / 服务会话、CAS PGT/PT，以及 OIDC 持久化签名密钥。

迁移文件已嵌入可执行文件，并在 `certus_schema_migrations` 中记录版本与 SHA-256 校验和；已执行的 migration 被修改时，服务会拒绝启动。

## 统一用户管理

用户主档由 Certus 统一维护，业务系统只消费认证结果和用户标识。当前支持：

- 用户名和邮箱唯一性约束
- 用户名、显示名称和邮箱搜索
- 分页与状态筛选
- `active`、`locked`、`disabled` 生命周期状态
- 更新显示名称、邮箱和状态
- 内存与 PostgreSQL 两种仓储

管理 API 默认关闭。设置至少 32 个字符的随机 Bearer Token 后启用：

```powershell
$env:CERTUS_ADMIN_TOKEN='<至少 32 个字符的随机密钥>'
go run ./cmd/certus
```

请求通过 `Authorization: Bearer <token>` 鉴权：

```text
GET  /api/v1/admin/users?q=&status=&limit=20&offset=0
POST /api/v1/admin/users
GET  /api/v1/admin/users/{user_id}
PUT  /api/v1/admin/users/{user_id}
PUT  /api/v1/admin/users/{user_id}/password
POST /api/v1/admin/users/{user_id}/password-reset
GET  /api/v1/admin/users/{user_id}/sessions
DELETE /api/v1/admin/users/{user_id}/sessions
DELETE /api/v1/admin/users/{user_id}/sessions/{session_id}
GET  /api/v1/admin/audit-events
```

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

服务端只保存 Argon2id 哈希；连续失败 5 次会锁定凭据 15 分钟。

管理员密码重置接口返回一个仅显示一次、30 分钟有效的 `reset_token`，交付通道由部署方接入邮件或工单系统。账号自助接口使用当前登录会话：

```text
GET    /api/v1/account/sessions
DELETE /api/v1/account/sessions/{session_id}
PUT    /api/v1/account/password
POST   /api/v1/account/password/reset
```

用户改密必须提交 `current_password` 与 `new_password`，成功后保留当前会话并撤销其他会话；一次性重置成功后撤销全部会话。审计接口支持 `actor_user_id`、`event_type`、`client_id`、`outcome`、`from`、`to` 与分页筛选。

### LDAP 与外部 OIDC

客户端在 `login_methods` 中选择 `ldap` 或 `oidc` 后，还需要配置对应的全局身份源。LDAP 支持服务账号搜索后以最终用户 DN 绑定：

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
GET  /admin/clients
GET  /api/v1/admin/clients
POST /api/v1/admin/clients
GET  /api/v1/admin/clients/{client_id}
PUT  /api/v1/admin/clients/{client_id}
DELETE /api/v1/admin/clients/{client_id}
POST /api/v1/admin/clients/{client_id}/secret
GET  /api/v1/admin/clients/{client_id}/integration
```

`/admin/clients` 提供可直接使用的配置页面。管理员令牌只保存于当前浏览器的 `sessionStorage`，关闭会话后自动清除。

创建配置：

```json
{
  "id": "finance",
  "name": "Finance",
  "description": "财务系统",
  "application_type": "confidential",
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
  "login_methods": [
    "password",
    "ldap"
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
    "client_secret": "<仅本次响应显示>",
    "client_authentication_method": "client_secret_basic",
    "authorization_endpoint": "https://auth.example.com/oauth2/authorize",
    "token_endpoint": "https://auth.example.com/oauth2/token",
    "introspection_endpoint": "https://auth.example.com/oauth2/introspect",
    "revocation_endpoint": "https://auth.example.com/oauth2/revoke",
    "userinfo_endpoint": "https://auth.example.com/oauth2/userinfo",
    "jwks_uri": "https://auth.example.com/oauth2/jwks",
    "redirect_uris": [
      "https://finance.example.com/oidc/callback"
    ],
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

`public` 客户端不生成密钥；`confidential` 客户端的明文密钥只在创建响应中出现一次，Certus 只保存 SHA-256 哈希。非本机回环地址的回调必须使用 HTTPS，回调地址在授权时执行精确匹配。

`PUT` 采用完整替换语义，但 `client_id` 和客户端类型保持不可变；通过 `enabled:false` 可暂停新登录和令牌签发。`POST .../secret` 立即轮换机密客户端的密钥，新明文同样只显示一次。`DELETE` 执行软归档并同时禁用客户端，历史令牌、授权和审计记录不会因物理删除而丢失。

## 角色与权限下发

角色和权限点始终按 `client_id` 隔离，用户可被授予带过期时间的临时角色。管理接口如下：

```text
GET  /api/v1/admin/clients/{client_id}/roles
POST /api/v1/admin/clients/{client_id}/roles
GET  /api/v1/admin/clients/{client_id}/permissions
POST /api/v1/admin/clients/{client_id}/permissions
GET  /api/v1/admin/clients/{client_id}/roles/{role_id}/permissions
PUT  /api/v1/admin/clients/{client_id}/roles/{role_id}/permissions
GET  /api/v1/admin/users/{user_id}/roles?client_id=
PUT  /api/v1/admin/users/{user_id}/roles
```

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
- OAuth 令牌管理：受客户端认证保护的 Introspection 与幂等 Revocation
- OpenID Connect：通过 `openid` scope 为 OAuth 登录提供用户身份
- CAS 1.0、2.0、3.0：Service Ticket 校验参数
- CAS 2.0/3.0：代理认证
- CAS：Gateway、Renew 和单点登出选项

OAuth 2.1 当前仍是 IETF Internet-Draft。出于安全原因，Certus 不开放 OAuth implicit 和 resource owner password grant；OAuth Security BCP 已明确不应使用这些遗留流程。

## 构建与发布

[`.github/workflows/release.yml`](.github/workflows/release.yml) 支持两种触发方式：

- 在 GitHub Actions 页面使用 `workflow_dispatch` 手动执行，可指定版本并选择是否推送镜像。
- 向 `release` 分支提交代码时自动执行。

每次运行都会先执行测试与静态检查，然后生成以下服务端包：

```text
Linux   amd64 / arm64
Windows amd64 / arm64
macOS   amd64 / arm64
```

各平台压缩包、独立 SHA-256 文件和总 `SHA256SUMS` 会保存为 GitHub Actions artifacts。二进制支持查看构建信息：

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
  ghcr.io/devshuai/certus:release
```

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
web                        登录页和中间落地页
```

协议执行数据默认持久化到 PostgreSQL；未设置数据库地址时使用仅供开发和测试的内存实现。

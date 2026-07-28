<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
  <img alt="certus 统一认证中心" src="docs/assets/logo-light.svg" width="280">
</picture>

# Certus

Certus 是使用 Go 开发的统一认证中心，面向账号、单点登录、OAuth 2.1、OpenID Connect、令牌和权限管理场景。

## 当前骨架

- 可优雅关闭的 HTTP 服务
- 环境变量配置与结构化日志
- 健康检查、请求 ID 和基础安全响应头
- 登录页与认证后的中间落地页
- 接入系统领域模型、内存仓储与只读查询 API
- 按接入系统动态展示登录方式
- OAuth 2.1 授权请求入口校验（精确回调地址、state、OIDC scope、PKCE S256）
- OpenID Connect Discovery 元数据
- 可选 PostgreSQL 连接池与内嵌、带校验和的自动迁移
- PostgreSQL 客户端仓储；未配置数据库时自动使用开发内存仓储
- 无第三方依赖的基础测试

Discovery 中声明的令牌和 JWKS 端点是后续实现目标；在完成密钥与授权码服务前，不会签发令牌。

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

迁移文件已嵌入可执行文件，并在 `certus_schema_migrations` 中记录版本与 SHA-256 校验和；已执行的 migration 被修改时，服务会拒绝启动。

## 规划中的模块边界

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

建议下一阶段先实现客户端注册、PostgreSQL 数据模型、账号密码登录和带 PKCE 的授权码流程。

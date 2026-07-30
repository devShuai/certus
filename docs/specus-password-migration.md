# Specus 用户密码迁移到 Certus

## 迁移的数据

Specus 管理用户存放在 `specus_management_user`，密码字段 `password_hash` 是小写十六进制 SHA-256。已验证邮箱位于 `specus_management_user_email`。建议至少导出：

- `username`
- `password_hash`
- `enabled`
- `email`
- `role`
- `tenant_id`

Certus 当前用户名只允许 3–64 位小写字母、数字、点、下划线和连字符。导入前必须确定不兼容用户名的稳定映射，并同步更新 Specus 中按用户名保存的资源归属。`tenant_id` 和 Specus 原角色不会由密码导入接口自动映射。

## 迁移请求

把导出结果转换成以下 JSON，每批不超过 1000 个用户：

```json
{
  "password_algorithm": "specus_sha256",
  "expires_at": "2026-10-29T00:00:00Z",
  "users": [
    {
      "username": "alice",
      "display_name": "alice",
      "email": "alice@example.com",
      "status": "active",
      "password_hash": "64 位 SHA-256 十六进制摘要"
    }
  ]
}
```

Specus 的 `enabled=true` 映射为 `active`，否则映射为 `disabled`。Specus 没有独立显示名称时可暂时使用原用户名。请求发送到：

```http
POST /api/v1/admin/users/import
Authorization: Bearer <CERTUS_ADMIN_TOKEN>
Content-Type: application/json
```

也可以使用具备 `admin.users.write` 权限且已完成 MFA 的管理员会话调用。应急令牌和导出文件都属于高敏感数据，不要写入 Git、终端历史或普通日志。

## 执行顺序

1. 备份 Specus 和 Certus 数据库，短暂停止 Specus 用户注册与改密。
2. 导出用户，在隔离环境完成用户名、邮箱、状态和摘要格式校验。
3. 分批调用导入接口。任一条冲突会回滚该批全部用户；接口不会覆盖 Certus 已有账号。
4. 为普通用户授予 Certus 客户端角色 `specus_user`，仅为原管理员授予 `specus_admin`。
5. 选择测试账号使用原 Specus 密码登录 Certus，确认登录后凭据已升级为 Argon2id。
6. 配置 Specus 使用 Certus OIDC，迁移观察期内保留本地密码回退。
7. 在旧凭据到期前通知尚未登录的用户；到期后只能通过密码重置激活。
8. 完成切换后关闭 Specus 注册和本地密码登录，安全删除所有摘要导出文件。

旧凭据默认从导入起有效 90 天，最多允许 365 天。每次失败仍受 Certus 的来源和账号限流、连续失败锁定及审计保护。首次成功验证后，Certus 必须先成功写入 Argon2id 摘要才会放行登录。

<!-- 放在 certus README.md 顶部,GitHub 按读者主题自动切换 -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
  <img alt="certus 统一认证中心" src="docs/assets/logo-light.svg" width="280">
</picture>

# certus

统一认证中心 —— 为 specus 及各内部服务签发与校验身份。

---

## 配色

| 角色 | 明色底 | 暗色底 |
| --- | --- | --- |
| 底块 | #14161F | #14161F |
| 主笔画 | #14161F（无底块时）/ #F2F3F7（底块上） | #F2F3F7 |
| 强调（对勾） | #C98A1E | #E8B34A |
| 副标文字 | #6B6E7B | #9A9DA8 |

specus 用紫罗兰 #7A5CE6 / #9B82FF,certus 用琥珀金 —— 同一深灰骨架,靠强调色区分产品。

## 文件放置

| 文件 | 仓库位置 |
| --- | --- |
| logo-light.svg / logo-dark.svg | docs/assets/ |
| logo-mark.svg / logo-mark-dark.svg | docs/assets/ |
| logo.svg | apps/*-web/public/logo.svg |
| favicon.svg / favicon-32.svg / favicon-16.svg | apps/*-web/public/ |
| AppLogo.tsx | apps/*-web/src/components/AppLogo.tsx |

### index.html 引用

```html
<link rel="icon" type="image/svg+xml" sizes="any" href="/favicon.svg" />
<link rel="icon" type="image/svg+xml" sizes="32x32" href="/favicon-32.svg" />
<link rel="icon" type="image/svg+xml" sizes="16x16" href="/favicon-16.svg" />
```

小尺寸说明:32px 加粗笔画,16px 再加粗并让对勾贯穿到边 —— 每档单独出图,不靠浏览器缩放。

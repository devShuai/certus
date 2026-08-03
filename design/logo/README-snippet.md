<!-- 放在 certus README.md 顶部,GitHub 按读者主题自动切换 -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
  <img alt="certus 统一认证中心" src="docs/assets/logo-light.svg" width="280">
</picture>

# certus

统一认证中心 —— 为 specus 及各内部服务签发与校验身份。

图形取自**虎符**:两半分持、咬合验真。深色半是签发方,琥珀半是持凭者。

---

## 配色

| 角色 | 明色底 | 暗色底 |
| --- | --- | --- |
| 图标底块（仅 favicon） | #14161F | #14161F |
| 左半（签发方） | #14161F | #F2F3F7 |
| 右半（持凭者） | #C98A1E | #E8B34A |
| 字标 | #14161F | #F2F3F7 |
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

横版字标（logo-light / logo.svg）不带深色底块,直接落在页面上;favicon 带底块,因为应用图标需要自己的边界。

### index.html 引用

```html
<link rel="icon" type="image/svg+xml" sizes="any" href="/favicon.svg" />
<link rel="icon" type="image/svg+xml" sizes="32x32" href="/favicon-32.svg" />
<link rel="icon" type="image/svg+xml" sizes="16x16" href="/favicon-16.svg" />
```

小尺寸:32px 笔画加到 6,16px 两半转实心 —— 每档单独出图,不靠浏览器缩放。

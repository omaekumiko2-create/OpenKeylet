# Chrome 商店上架材料

此目录包含 OpenKeylet 扩展的上架文案、数据声明、审核指引、代码审查和真实界面素材。当前是待提交材料，不代表已经上传、审核通过或公开发布。

## 可直接使用的材料

| 材料 | 文件 |
| --- | --- |
| 英文商店文案 | [listing.en.md](listing.en.md) |
| 中文商店文案 | [listing.zh-CN.md](listing.zh-CN.md) |
| 单一用途、权限理由、隐私字段填写指南 | [privacy-practices.md](privacy-practices.md) |
| 审核测试指引 | [reviewer-instructions.md](reviewer-instructions.md) |
| 英文隐私政策 | [PRIVACY.md](../../PRIVACY.md) |
| 中文隐私政策 | [PRIVACY.zh-CN.md](../../PRIVACY.zh-CN.md) |
| 随包离线隐私说明 | [privacy.html](../../browser-extension/privacy.html) |

## 提交前需要确定

- 发布者显示名称和已验证的公开联系邮箱：由账号所有者填写，材料不虚构个人资料。
- 在开发者后台完成注册、两步验证及真实的 Trader / Non-Trader 声明。
- 把隐私政策发布到可公开访问、无需登录的页面，并把实际生效网址填入 Privacy policy URL。仓库文件在提交并公开前不能当作已上线网址。
- 提供与当前扩展匹配的桌面应用发行包。现有 `releases/latest` 只是下载入口，必须核对线上版本是否包含本次密码库和桥接功能。
- 首次只上传 ZIP 为草稿，取得商店 ID 和公钥。核对 `src-tauri/src/browser.rs` 的 `EXTENSION_ORIGIN`、开发用 manifest `key` 与集成测试 ID；如果不同，更新为商店身份、重建桌面端并验证配对。不要改成接受任意扩展 Origin。
- 用实际商店安装的版本验证配对、权限、网站访问设置和升级。开发者模式测试不能替代这一步。
- 以最终发布行为核对隐私字段、功能范围与图片；取得真实账号资料后填入后台。当前商店文案明确要求桌面应用，不宣称独立运行。

## 生成上传包

在 Windows PowerShell 中先加载项目环境，再运行：

```powershell
& "$env:MYENV_ROOT\config\Use-ProjectEnvironment.ps1" -ProjectPath (Get-Location).Path -Quiet
& .\scripts\package-chrome-store.ps1
```

ZIP 与校验值输出到 `dist/chrome-web-store/`。临时打包目录必须在 `MYENV_ROOT` 内。脚本只包含扩展运行文件，不包含桌面 EXE、测试密码库、源码仓库元数据或上架文档。它删除上传副本中的开发用 `key`，保留源码中的固定开发 ID；正式 ID 仍须按上面的流程确认。

## 发布顺序

完成身份与资料 → 上传草稿取得商店身份 → 校准桌面端与扩展身份 → 发布兼容桌面包及隐私政策 → 用商店安装包测试 → 提交审核 → 审核通过后发布。

版本更新必须增加扩展版本号。后续可以接入 Chrome Web Store V2 API 自动上传和送审，审核本身仍由 Google 完成。

## 官方参考

核对日期：2026-10-20。

- [发布流程](https://developer.chrome.com/docs/webstore/publish)
- [隐私字段](https://developer.chrome.com/docs/webstore/cws-dashboard-privacy)
- [开发者政策](https://developer.chrome.com/docs/webstore/program-policies/policies)
- [图片要求](https://developer.chrome.com/docs/webstore/images)
- [固定扩展 ID](https://developer.chrome.com/docs/extensions/reference/manifest/key)
- [审核流程](https://developer.chrome.com/docs/webstore/review-process)

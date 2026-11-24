# 中文商店文案

## 名称

OpenKeylet — 本地密码与 Passkey

## 简介

连接 OpenKeylet 桌面密码库，在浏览器中管理密码、Passkey、信用卡和身份资料。需要运行 OpenKeylet 桌面应用。

## 详细介绍

把本地 OpenKeylet 桌面密码库的零明文 Agent 桥接与当前网站快捷填入能力带到 Chrome：填写与保存当前网站登录、复制实时 2FA 验证码、使用 Passkey，并在当前页快速填写已保存的信用卡与身份表单。

需要安装并运行免费的 OpenKeylet 桌面应用并开启 Browser Bridge。完整密码库管理、回收站、历史记录与备份保留在桌面端；本扩展作为最小权限伴侣扩展，无需 OpenKeylet 账号。

方便地使用密码

选择当前网站匹配的账号填写用户名与密码，或一键复制 2FA 验证码；检查网页表单后手动保存登录信息。也可主动开启登录、注册和修改密码的保存提示。待保存内容仅临时保存在内存中，必须经你确认才能写入密码库。

经过确认的 Passkey

支持的 Passkey 注册和登录会打开独立确认窗口。私钥保留在本地桌面密码库中；可选择“Use device”返回浏览器原生流程。部分网站和高级 WebAuthn 功能使用原生提供方。

当前页卡片与身份快速填充

在 HTTPS 网站上直接选择桌面密码库中已保存的信用卡或身份资料一键填写表单；项目的编辑、删除、回收站恢复与密码历史管理统一在 OpenKeylet 桌面端完成。

本地连接，自主选择

扩展通过本机连接与 OpenKeylet 通信，不含广告或内置使用分析。可选的 GitHub 加密备份在桌面端单独配置。通过桌面 MCP 服务接入 AI Agent 后，Agent 可请求已启用的凭据操作，包括填写当前聚焦的浏览器字段，以及明确请求的表单提交。

开始使用

1. 下载并运行兼容版本的 OpenKeylet 桌面应用。
2. 开启 Browser Bridge，按照指引配对。
3. 安装扩展并固定到工具栏。
4. 打开网站，按需使用 OpenKeylet PIN 解锁，再选择操作。
5. 如需自动识别待保存的登录信息，在扩展中主动开启保存提示。

桌面端下载：https://github.com/omaekumiko2-create/OpenKeylet/releases/latest
说明与支持：https://github.com/omaekumiko2-create/OpenKeylet

功能范围

浏览器设置等内部页面不能填写。密码、信用卡和身份表单流程要求 HTTPS 或本机开发地址。复杂表单、跨来源支付 iframe、硬件证明及高级 Passkey 功能可能需要手动操作或原生提供方。普通弹窗填写不会提交表单；Agent 请求提交是由桌面端发起的单独操作。

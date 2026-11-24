<p align="center">
  <img src=".github/assets/openkeylet-hero.svg" alt="OpenKeylet 面向 AI Agent 的本地 MCP 密码与凭据管理器" width="100%" />
</p>

<h1 align="center">OpenKeylet — 跨平台 AI Agent 密码库与凭据输入器</h1>

<p align="center">
  <strong>一个本地 MCP 凭据中继工具：不中断 Agent 工作流，也不必让 Agent 接触隐藏的明文。</strong>
</p>

<p align="center">
  本地优先&nbsp;&nbsp;·&nbsp;&nbsp;免费开源&nbsp;&nbsp;·&nbsp;&nbsp;无需 OpenKeylet 账号&nbsp;&nbsp;·&nbsp;&nbsp;Windows / macOS / Linux
</p>

<p align="center">
  <a href="../../releases/latest"><strong>下载 OpenKeylet</strong></a>
  &nbsp;&nbsp;·&nbsp;&nbsp;
  <a href="README.md">English</a>
  &nbsp;&nbsp;·&nbsp;&nbsp;
  <a href="SECURITY.zh-CN.md">安全说明</a>
</p>

---

OpenKeylet 是一个免费开源、跨平台的 AI Agent 密码管理器、凭据保险库与本地 `stdio` MCP 服务。Codex、Claude Code、Cursor、OpenCode、Antigravity、DeepSeek Harness 等 MCP 客户端可以通过 OpenKeylet 使用已保存的密码、API 凭据、SSH 私钥、TOTP 与自定义秘密，同时让默认隐藏的明文保持在普通模型上下文之外。

当 Agent 需要登录网站、连接服务器、调用认证 API，或在终端中完成密码输入时，可以让 OpenKeylet 在本地完成凭据步骤，不必把秘密粘贴进对话。

**OpenKeylet 原名 KRU。** 改名后继续使用原有的本地密码库、加密密钥、浏览器配对和 `.mvault` 备份格式。旧的 `{{kru:模块名}}` 占位符以及 `KRU_DATA_DIR` / `KRU_LAUNCHER_PATH` 环境变量仍然可用；新配置请使用 `{{openkeylet:模块名}}` 和 `OPENKEYLET_*`。升级后，打开 **设置 → Agent 接入 → 修复**，将托管的 `kru` MCP 配置迁移为 `openkeylet` 并更新程序路径，然后新建 Agent 会话。新版 GUI 启动时会迁移原有的桌面和开机启动快捷方式。

## 你可以这样用

连接 OpenKeylet 后，像平常一样描述任务即可。写出唯一的 OpenKeylet 项目名可以获得最准确的匹配；不知道项目名时，也可以直接让 Agent 在需要认证时检查 OpenKeylet。

| 目的 | 可以直接这样说 |
| --- | --- |
| **服务器任务** | `使用 OpenKeylet MCP 中的「生产服务器」部署当前版本，并验证服务状态。` |
| **认证 API** | `使用 OpenKeylet MCP 中的「域名服务」，列出当前账号下的域名。` |
| **网页登录** | `打开管理后台；需要凭据时，使用 OpenKeylet MCP 中的「管理账号」。` |
| **自动查找** | `继续完成任务；如果中途需要认证，先检查 OpenKeylet。` |

引号中的文字就是保存在 OpenKeylet 内的项目名。省略名称时，Agent 可以先读取 OpenKeylet 项目列表并选择匹配项。

## OpenKeylet 是什么

OpenKeylet 是一个用于保存和使用凭据的小型本地 MCP 工具。Agent 负责完整任务流程，OpenKeylet 在本地完成填写、运行本地或 SSH 命令、传输文件与目录，以及发送已认证的 API 请求，因此工作流无需中断，默认隐藏的明文也不会返回给 Agent。

个人保险库支持登录、信用卡、身份资料、安全笔记、SSH、API 和自定义项目，并提供类型筛选、文件夹与收藏。字段仍可自由组合；账号、密码、卡号、安全码、身份地址和安全笔记均作为加密字段保存。公开用途、名称和文件夹属于项目元数据。

浏览器插件支持登录密码与 Passkey，以及信用卡、身份资料的新增、编辑和手动填写，修改直接写入同一个本地密码库。支持标准 HTML `autocomplete`、常见字段名与标签、月份控件、到期年月格式和下拉选项；跳过隐藏、透明、禁用和只读控件。聚焦相关表单时只填写该表单。只在 HTTPS 网站（或本机测试地址）上执行，不自动提交表单，也不跨来源填写 iframe。完整卡号和安全码不会出现在列表中。复杂支付组件、第三方支付 iframe 和非标准字段仍可能需要手动填写。

桌面端与插件均有密码生成器，可选 8–128 位、大写、小写、数字与符号，使用系统安全随机数；不会保存生成历史。

插件的「完整密码库」在浏览器管理页和普通网站上都可使用，支持搜索、类型筛选、文件夹、收藏、登录网址与匹配规则，以及信用卡、身份和笔记编辑。删除项目会先移入「回收站」，保留到你恢复或永久删除；回收站项目不能填写密码或签署 Passkey 登录。恢复时如有同名项目，会自动改名，避免覆盖。

修改已保存的密码会加密保留最近 20 条旧密码。桌面端与插件解锁后可以查看、复制或清除「密码历史」；Agent 和自动填写无法请求旧密码。完整备份同时包含回收站和密码历史。永久删除或清除历史不会修改已有备份中的旧副本。

OpenKeylet 没有自有账号、订阅、托管密码库或远程 MCP 服务。它免费开源，支持 Windows、macOS 和 Linux，保险库在当前设备本地加密保存。可选的 GitHub 备份将加密快照保存到用户自己的私有仓库。本地 `stdio` MCP 只在 Agent 调用时启动。

<table>
  <tr>
    <td width="33%"><strong>01 / 保存</strong><br><br>只添加项目真正需要的模块，所有凭据在本机加密。</td>
    <td width="33%"><strong>02 / 发现</strong><br><br>Agent 看到项目名、字段名、非秘密目标和可用动作。</td>
    <td width="33%"><strong>03 / 使用</strong><br><br>OpenKeylet 在本地执行凭据操作，不返回默认隐藏的明文。</td>
  </tr>
</table>

<p align="center">
  <img src=".github/assets/openkeylet-flow.svg" alt="AI Agent 找到凭据项目后由 OpenKeylet 在本地使用隐藏秘密" width="100%" />
</p>

## 三步开始使用

1. **下载并打开 OpenKeylet**
   选择对应平台的便携包，无需注册账号。

2. **连接 Agent**
   打开 **设置 → Agent 接入**，连接检测到的客户端，然后新建一个 Agent 会话。

3. **保存一个项目**
   设置不可重复的项目名称，只添加真正需要的模块；既可以选择预设，也可以从空白开始组合。

OpenKeylet 注册的是本地 `stdio` MCP。Agent 调用时才会启动对应 MCP 进程。

## MCP 客户端兼容性

OpenKeylet 的 Agent 接入界面可以检测、连接并修复 **Codex**、**Claude Code**、**Cursor**、**OpenCode**、**Antigravity** 与 **DeepSeek Harness** 的本地配置。其他 AI 助手或编程 Agent 只要支持本地 `stdio` MCP 服务，也可以使用下方的手动配置接入。

## 一个项目，多种动作

| 动作 | 自动开放条件 | OpenKeylet 在本地完成 |
| --- | --- | --- |
| **填写** | 项目包含任意凭据模块 | 把选定值写入已聚焦的浏览器、桌面控件或托管终端 |
| **SSH** | 项目包含密码或私钥 | 在本地认证；主机、端口和账号既可保存为默认值，也可随任务临时提供 |
| **文件传输** | 项目包含密码或私钥 | 通过 SFTP 递归上传或下载文件与目录 |
| **HTTP** | 项目包含任意已配置秘密 | 注入内置认证，或在本地解析隐藏模块占位符 |
| **终端** | Agent 运行本地命令或打开托管终端 | 在本地替换隐藏模块，但不把秘密返回给 Agent |

同一项目可以开放多个动作。OpenKeylet 没有观察、诊断、受限或执行模式：项目开放 `ssh_run` 后，Agent 直接提交任务真正需要的命令。

## 每个模块独立控制明文

每个模块都有自己的 Agent 可见性开关：

- **隐藏** — 凭据模块的默认状态。OpenKeylet 可以使用该值，但 MCP 返回中不会包含它。
- **可见** — 只有用户明确打开开关后，该值才允许返回给 Agent。
- **TOTP** — OpenKeylet 只生成当前六位验证码，永久种子不会返回。

编辑器中的查看与复制按钮供本机用户使用。复制密码、2FA 验证码、生成器密码或恢复密钥时，会标记跳过 Windows 剪贴板历史并在 30 秒后自动清除（仅在剪贴板内容未被覆盖时清除，锁屏或退出时也会立即清理）。可选六位 PIN 用于防止他人在本机查看明文或管理密码库（支持可选空闲自动锁定与输错冷却），并用于扩展密码库与 Passkey 验证；它不代替系统锁屏、保险库加密或加密备份口令，也不会关闭后台 MCP 动作。

模块通过左侧拖动把手调整顺序，也可以聚焦把手后使用上、下方向键。输入框内可以正常输入、选择和复制文字。删除项目、模块或草稿前会显示确认；模块删除在保存项目后生效。

## 为本地使用而设计

<table>
  <tr>
    <td width="33%"><strong>加密保险库</strong><br><br>字段使用 XChaCha20-Poly1305 加密，机器主密钥留在本机。</td>
    <td width="33%"><strong>便携备份</strong><br><br>导出加密的 <code>.mvault</code> 包，在其他设备上导入使用。</td>
    <td width="33%"><strong>本地记录</strong><br><br>记录哪个客户端请求了什么动作，但不记录秘密值。</td>
  </tr>
</table>

## 浏览器、SSH 与 API

### 浏览器填写

随包提供的 Chromium 扩展与桌面软件共用同一份本地加密密码库。打开 **设置 → Browser Bridge**，按编号完成两步：**1. 打开扩展页**，点击“打开浏览器并复制地址”，粘贴到 Chrome 地址栏并打开，然后开启右上角的“开发者模式”；**2. 拖入插件**，将 OpenKeylet 标识拖到扩展页空白区域后松开。“拖拽无法安装？”中保留了扩展目录按钮，可配合“加载已解压的扩展程序”手动安装。安装后保留 `browser-extension` 文件夹，扩展会自动配对。新版扩展使用固定 ID；升级旧扩展时请重新加载，必要时移除旧版后重新安装并配对。

点击浏览器工具栏的 OpenKeylet 图标，可选择当前网站的账号并填写用户名与密码。未设置专门规则时，匹配协议、主机和端口。桌面项目编辑器支持多个网站，以及同源、主域名、主机、完整网址、前缀、正则和“不匹配”规则；填写会校验实际目标 frame 的完整地址，并在写入前再次核对。不会自动提交表单。点击“保存当前网站的账号”读取页面表单，再确认新建或更新本地项目；扩展和桌面端会刷新同一份数据，并阻止覆盖已发生变化的项目。配置 PIN 后，扩展需要解锁，解锁会话有效期为五分钟。软件及 Browser Bridge 需要保持运行。

自动保存提示默认关闭。在插件弹窗开启「登录或注册后提示保存」后，提交登录、注册或修改密码表单时会显示「预览保存」提示和工具栏 `+` 标记。自动识别账号及新密码，排除隐藏字段、验证码和支付字段；密码不一致或无法明确选择时不自动生成建议。在扩展窗口中核对来源网站和内容，必要时先解锁，再确认新建或更新已有账号。提交表单不代表登录或注册成功；密码库解锁时，未变化的已有账号不会重复提示。待保存信息只保留在插件后台内存中，最长五分钟；忽略、在插件中主动锁定、连接断开、关闭标签页或跳转到其他来源时清除。关闭此选项会停止采集并清除待保存建议。

支持 HTTPS／本机测试网页的标准表单提交、可识别的登录或注册按钮、回车提交、动态表单、开放的 Shadow DOM 和同源 frame。「下一步／继续」提交的用户名可在同一标签页、frame 和来源的后续密码步骤中使用，仅保留在内存中，最长两分钟；锁定、断开连接或关闭保存提示时同样清除。密码填写会触发 input/change 事件，兼容 React 受控输入框和 Vue 模型。封闭的 Shadow DOM、跨来源分步登录、含糊字段和没有可识别标签的自定义按钮，仍可能需要手动填写或「保存当前网站的账号」。

网站发起 Passkey 创建或登录时，OpenKeylet 会打开独立确认窗口。创建的 Passkey 作为独立项目保存在本地密码库，私钥始终在桌面端加密保存，扩展只接收注册结果和登录签名。要求身份验证的网站需要先在 OpenKeylet 设置六位 PIN，每次 Passkey 请求都重新验证 PIN。可在确认窗口选择“使用设备或安全密钥”返回浏览器原生流程。桌面项目编辑器显示 Passkey 的网站与账号；移入回收站后停用，恢复后可继续使用，永久删除才会移除本机凭据。

当前 Passkey 支持 HTTPS 顶层页面及本机 `localhost`、ES256、可发现凭据和指定凭据登录。跨域 iframe、条件式自动填充、硬件认证证明及高级 WebAuthn 扩展不由此版本接管；不兼容的请求应使用设备原生流程。现有其他提供方的 Passkey 不会自动迁入。

Agent 的 `credential_fill` 仍把一个选定字段写入聚焦控件；显式设置 `submit=true` 时可提交所属表单。该路径不执行上述网站账号匹配，也不导出 Cookie。

### SSH

OpenKeylet 支持密码与私钥认证、不限制长度的命令与输出、直接传入标准输入，以及递归 SFTP 上传/下载。主机、端口和账号既可保存为默认值，也可在当前任务中临时提供。目标父目录会自动创建，已有文件或目录只会在完整临时副本准备好后替换。OpenKeylet 不固定或比较 SSH 服务器指纹，认证明文不会返回给 Agent。

### HTTP API

OpenKeylet 会识别常见 API 服务与 Basic 认证组合，无法识别时使用 Bearer Token。保存的服务 URL 只是默认地址和相对路径基准，不是 Origin 限制；Agent 可按任务使用任意 HTTP/HTTPS 目标。其他协议可在 URL、Header、Query、JSON/文本正文或表单中写 `{{openkeylet:模块名}}`，由 OpenKeylet 在本地解析。重定向会正常跟随，响应默认没有大小上限，也可直接流式保存到本地文件，并支持 multipart 文件上传。

## 本地程序设置

设置页包含：

- 创建桌面快捷方式（受支持的平台）与开机自启动；
- 关闭到托盘或真正退出；
- 可选六位本地 PIN；
- Agent 接入、扫描与修复；
- Browser Bridge 配对；
- 可选的 GitHub 私有仓库加密备份与换机恢复；
- 加密备份导入、导出与打开本地数据目录。

替换或升级可执行文件不会删除保险库。OpenKeylet 会继续读取当前系统用户的数据目录：

| 平台 | 保险库位置 |
| --- | --- |
| Windows | `%APPDATA%\mcp-vault\v2` |
| macOS | `~/Library/Application Support/mcp-vault/v2` |
| Linux | `${XDG_DATA_HOME:-~/.local/share}/mcp-vault/v2` |

桌面端导出的 `.mvault` 使用独立备份密码（至少 12 个字符），通过 Argon2id（64 MiB、3 次、1 并行）派生密钥，再用 XChaCha20-Poly1305 加密完整备份；文件内不包含解锁密钥。恢复时需要原密码。旧版和现有 CLI 自动解锁包仍可导入，其文件包含解锁材料，须像原始凭据一样保护。

### 可选个人加密密码仓库（GitHub / Gitea / Forgejo）

在 **设置 → CLOUD / 05** 中，你可以自愿连接一个属于自己的私有仓库来存储和跨设备同步加密密码库（非强制）：

1. 点击“设置 GitHub 备份”，选择托管平台（**GitHub** 或自建 HTTPS **Gitea / Forgejo**）与授权方式。GitHub 可复用本机 [GitHub CLI 登录](https://cli.github.com/manual/gh_auth_login)或填写 [GitHub 细粒度访问令牌](https://github.com/settings/personal-access-tokens/new)；Gitea/Forgejo 填写 HTTPS 服务器地址与访问令牌。
2. 点击“检查账号”，确认实际授权账号，再填写 `owner/repository`。连接已有私有仓库时，令牌仅需选择该仓库并授予 **Contents: Read and write**。
3. 没有仓库时，可勾选“由 OpenKeylet 在我的账号下创建此私有仓库”。需要具备创建仓库的授权（细粒度令牌还需 **Administration: Write**）；组织仓库请先在 GitHub 网页创建。已有同名仓库不会被接管或修改可见性，取消此选项即可按现有仓库连接。
4. 选择“创建新备份”，生成恢复密钥，在仓库之外保管并勾选确认。可按需开启“自动双向同步”，在修改或启动时后台防抖同步。保留“立即上传第一份加密备份”时，按钮为“连接并上传”；取消勾选则只保存连接，之后再手动同步或备份。
5. 换机时选择“连接已有备份”，填写同一仓库、原恢复密钥及授权，再点击“立即同步”或“从云端恢复”。首次同步或恢复完成前会禁止覆盖上传。

GitHub CLI 授权只在你检查账号或提交连接时读取，不会把令牌返回界面或写入日志；连接成功后按现有方式加密保存在本机。首次上传失败会保留连接并显示错误，可以按提示重试，不必重新创建仓库。创建仓库结果不确定时，先在 GitHub 检查，再决定是否连接现有仓库。

完整的便携数据（包括项目名、地址、备注和凭据）在本地使用 XChaCha20-Poly1305 和独立随机生成的 256 位恢复密钥加密。GitHub 只接收 `openkeylet.vault.json`，其中没有解锁密钥。令牌与恢复密钥由当前设备的保险库主密钥加密保存，不包含在备份里。浏览器配对、PIN、Agent 接入配置、操作记录和草稿仍保留在各自设备；已解锁 GUI 可以查看保存的恢复密钥。

你可以随时使用**立即同步**（以及可选的**自动双向同步**）进行多设备双向合并，也可以继续使用**立即备份** / **从云端恢复**进行手动快照操作。双向同步按条目 `id` 与 `updatedAt` 合并变更、通过删除墓碑传播永久删除、在遇到远端 `409 Conflict` 时自动拉取合并并重试，并在内容指纹无变化时跳过空提交。手动“从云端恢复”仍保持非破坏性合并（跳过相同项目、冲突项另存）。每次上传、恢复和同步都会严格校验仓库为私有（`private: true`）。现已同时支持 GitHub.com 与自建 HTTPS Gitea/Forgejo 私有仓库，单份加密快照上限为 8 MiB。

恢复密钥丢失且没有仍连接的设备时，云端备份无法找回。Git 历史会保留旧版密文，包括已删除凭据；“断开”仅移除本机连接，不删除仓库历史或撤销 GitHub 令牌。旧版和 CLI 自解锁 `.mvault` 包不能直接作为安全的云同步密文上传。

新备份内部数据为 v8，包含项目类型、文件夹、收藏、网站匹配规则、Passkey、密码历史和回收站，仍可导入原有 v3/v4/v5/v6/v7 备份。现有 v7/v8/v9/v10/v11 保险库可直接读取，首次修改时保存为 v12。旧版程序不能读取 v12 保险库、新版密码保护容器或 v8 备份内容。

在 **系统 → 本地数据 → 迁入密码库** 中选择 Bitwarden 未加密 JSON，或 Chrome/Edge 密码 CSV。先预览项目数量及兼容性提示，再确认导入。取消不会改变密码库；确认后整批原子合并，相同项目去重，不覆盖已有项目。选中的文件只读取一次，待确认数据在内存中加密保存，五分钟后过期。

Bitwarden 导入保留登录、信用卡、身份、安全笔记、SSH 密钥、文件夹、收藏、备注、自定义字段和多网址规则。支持迁入 ES256/P-256 PKCS#8 Passkey，保留凭据 ID、用户标识与计数；旧版非零计数在返回登录签名前于密码库锁内更新，迁移后应避免继续使用这些凭据的另一副本。支持 Base32 和 `otpauth://totp`、SHA-1/SHA-256/SHA-512、6–8 位验证码及可配置周期；不支持的验证码密钥原样保留，并在预览中提示。

预览会说明尚未兼容的差异：附件需单独转移；关联字段以加密自定义字段保留；最近 20 条旧密码进入密码历史，更长的历史会同时归档到加密自定义字段中。逐项主密码验证和组织共享权限不会迁移。原回收站项目会跳过。不支持的项目类型、无效密钥或错误记录会使整次导入失败，不产生部分写入。原导出文件不会被修改或删除。

## 常见问题

### OpenKeylet 是面向 AI Agent 的密码管理器吗？

是。OpenKeylet 把本地加密的凭据保险库与可由 Agent 调用的 MCP 服务结合在一起，用于处理任务中的认证步骤，适合 AI 编程 Agent、终端 Agent 和其他本地 MCP 客户端。

### OpenKeylet 会把密码交给大模型吗？

默认不会。隐藏模块只由 OpenKeylet 在本地使用，不会出现在 MCP 返回或普通模型上下文中。流程确实需要该值时，用户可以明确打开某个模块的可见开关，让它返回给 Agent。

### OpenKeylet 可以保存和使用哪些凭据？

OpenKeylet 支持账号、密码、API Key 与 Token、SSH 私钥与口令、TOTP 种子、主机、端口、服务 URL 和自定义字段，并可在同一项目中自由组合这些模块。

### OpenKeylet 需要云端账号吗？

日常本地使用不需要账号。可选的 GitHub 加密备份需要用户自己的 GitHub 账号和私有仓库，不需要注册 OpenKeylet 账号。

## 下载

| 目标平台 | 格式 | 说明 |
| --- | --- | --- |
| Windows x64 | `.zip` | 便携 GUI、托盘、桌面输入与浏览器扩展 |
| macOS arm64 | `.zip` | 原生 `.app`；桌面输入需要辅助功能权限 |
| Linux x64 GUI | `.tar.gz` | AppImage GUI；桌面输入支持 X11 |
| Linux x64 无头版 | `.tar.gz` | 无 WebView 依赖；保留 MCP、SSH、HTTP、终端、备份与浏览器桥接 |

<p align="center">
  <a href="../../releases/latest"><strong>打开最新发布版本 →</strong></a>
</p>

<details>
  <summary>观看简短产品演示</summary>
  <p><a href="https://www.youtube.com/watch?v=GKQLEgAdbTU">在 YouTube 观看 OpenKeylet 演示 →</a></p>
</details>

## MCP 0.15 接口

OpenKeylet 直接使用唯一项目名，不再向 Agent 暴露内部 UUID。用户已经说出项目名且动作明确时，Agent 可以直接执行；显式使用项目或让 `items_search` 唯一命中后，它会成为当前 MCP 会话的轻量上下文，后续兼容的填写、SSH、传输、HTTP 和终端动作无需重复项目名。OpenKeylet 也能理解 `使用 OpenKeylet MCP 中的「生产服务器」` 这类自然表达。只有发现、切换、查看模块或消除歧义时才需要搜索。

绝不能要求用户提供隐藏的明文；未知字段和已停用的工具名会被拒绝。

每个 Agent 会话拥有自己的 stdio MCP 进程。启动新版 OpenKeylet 或另一个 Agent 会话不会中断已经进行中的任务；只有客户端结束会话，或用户从 OpenKeylet 托盘明确选择退出时，相关 MCP 进程才会结束。

| 工具 | 用途 | MCP 影响提示 |
| --- | --- | --- |
| `items_search(query?)` | 查找可用项目、模块和自动开放的动作 | 只读、幂等、本地 |
| `credential_fill` | 在已批准的本地目标中使用一个保存的模块，可选择同时提交 | 改变本地状态；提交可能产生外部影响 |
| `terminal_run` | 一步运行本地 shell 命令，可传入标准输入并替换隐藏模块 | 可能产生本地或外部影响 |
| `ssh_run` | 使用已保存身份及保存或临时提供的 SSH 目标执行命令 | 可能产生外部影响 |
| `ssh_upload` | 使用已保存身份递归上传本地文件或目录 | 读取本地路径并改变远端目标 |
| `ssh_download` | 使用已保存身份递归下载远端文件或目录 | 读取远端路径并改变本地目标 |
| `http_send` | 发送认证 HTTP 请求，可选择传输本地文件 | 可能产生外部及本地文件影响 |
| `terminal_start` | 启动托管本地进程 | 改变本地状态 |
| `terminal_write` | 向托管终端写入普通输入 | 可能产生外部影响 |
| `terminal_read` | 读取已脱敏的托管终端输出 | 只读、幂等、本地 |
| `terminal_stop` | 关闭托管终端会话 | 幂等状态变更 |

OpenKeylet 不提供不受限制的 `get_secret`。`items_search` 只返回项目与模块元数据、非秘密目标信息和自动推导的动作。只有用户明确打开 Agent 可见开关的凭据值才会出现在返回中；未知参数和已停用的旧工具名会被拒绝。

普通命令、脚本、JSON 或配置可直接通过 `terminal_run.stdin` 或 `ssh_run.stdin` 传入，无需 shell 转义或临时文件。命令、标准输入、路径、PTY 输入和 HTTP 请求字段都可用 `{{openkeylet:模块名}}` 引用隐藏模块。本地路径支持绝对路径、`~/...` 和相对 MCP 启动工作区的路径。OpenKeylet 不再对命令长度、SSH/终端输出、模块数量或并发终端数量设置固定上限；调用方仍可主动设置超时或响应大小限制。

每次成功的工具调用都会返回带类型的 `structuredContent` 及等价的 JSON 文本。业务失败返回带 `isError=true` 的 MCP 工具结果；格式错误的协议输入仍属于协议错误。工具注解帮助客户端说明影响，但实际安全限制全部由 OpenKeylet 后端执行。

手动配置 `stdio`：

```json
{
  "mcpServers": {
    "openkeylet": {
      "command": "C:\\absolute\\path\\to\\openkeylet.exe",
      "args": ["mcp", "stdio"]
    }
  }
}
```

也可以让 OpenKeylet 输出对应配置：

```text
openkeylet config stdio-json
openkeylet config stdio-toml
```

## 安全边界

OpenKeylet 的目标是避免默认隐藏的值进入正常 MCP 参数、返回值、操作记录、应用日志或 LLM API 流量。执行动作时，OpenKeylet 进程和最终目标仍会短暂接触明文。

OpenKeylet 不是沙箱，也不抵抗恶意 Agent、已被攻陷的系统或浏览器，以及本机同用户进程；它也无法判断 Agent 是否聚焦了正确输入框或选择了可信目标。将 OpenKeylet 用于敏感基础设施前，请阅读完整的[安全策略与威胁边界](SECURITY.zh-CN.md)。

## 从源码构建

需要 Rust 1.88+、Node.js 22+ 以及 [Tauri 2 平台依赖](https://v2.tauri.app/start/prerequisites/)。

```bash
npm install
npm run check
npm test
npm run build
npm run portable
```

浏览器集成测试使用独立 Chromium 配置加载真实扩展，并创建仅含测试凭据的临时密码库。安装 Playwright Chromium（`npx playwright install chromium`）后，运行 `npm run test:browser`。请按环境存储要求配置 `PLAYWRIGHT_BROWSERS_PATH`、`CARGO_TARGET_DIR` 和临时目录。测试覆盖密码同步、独立验证的 Passkey 注册与签名，以及取消流程；从桌面拖入 Chrome 的原生拖拽仍需手动检查。

登录兼容性测试入口：`npm run test:login-patterns -- --all-browsers` 覆盖 Chromium 和已安装的 Chrome、Edge；`npm run test:login-flows` 使用真实扩展、React/Vue 组件、动态表单和分步登录；`npm run test:login-capture` 检查保存确认、密码历史、隐私和来源隔离。可选的 `npm run test:public-logins` 只读取 GitHub、Google、微软、GitLab 公开登录页的字段结构，不输入账号、不提交表单。结构检查或模拟流程通过不代表真实网站认证已通过；验证挑战及无法访问的页面会标记为未验证。

其他平台发布命令：

```bash
npm run release:mac
npm run release:linux
npm run release:headless
```

## 许可证

[MIT](LICENSE) — 可以使用、检查和改进它。

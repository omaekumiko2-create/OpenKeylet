# 安全说明

[English](SECURITY.md) · **简体中文**

OpenKeylet 是一个按现状提供的开源公益便捷工具（不作任何形式的安全保障承诺），通过本地 stdio MCP 为 Agent 提供凭据存储与使用能力。它**不是**用于抵御恶意攻击者的严谨密码保险库，而是为了在保证 Agent 操作**无缝、快速**的前提下，尽量减少明文因低级失误出现在模型上下文、API 中转站、终端历史或公开仓库中。

## 安全目标

- Vault 秘密使用经过认证的加密方式静态存储。条目元数据和活动记录不加密，且默认模式下密钥保存在同一台机器上（见[本地数据与备份](#本地数据与备份)）。
- 未标记 `agentVisible` 的模块不会通过 `items_search` 返回明文。
- `credential_fill`、`terminal_run`、托管终端工具、`ssh_run`、`ssh_upload`、`ssh_download`、`http_send` 和 `secret_write_file` 可在本地使用隐藏值。
- 对 OpenKeylet 能识别的已存凭据（原值及常见编码：JSON 转义、base64 与 base64url（含嵌在更大编码内容中的值）、十六进制、百分号编码、shell 引号形式及多行值的单行），在活动错误、终端输出、SSH 输出、API 响应和浏览器检查结果中进行脱敏。每个终端、SSH、HTTP 和浏览器结果都会用本 MCP 会话替换、渲染、生成、导入、捕获或填写过的值（6 个字符及以上）、当前条目的隐藏值，以及所有已启用条目的隐藏秘密值（8 个字符及以上）进行脱敏，即使调用未指定任何条目。用户名、联系人与地址字段，以及名称和值都不像凭据的自定义字段（例如 `NODE_ENV=production`），只在使用其条目的调用中脱敏。
- 调用方不能替换 OpenKeylet 控制的认证头；条目保存了服务 URL 或网址规则时，`http_send` 只把其秘密发送到该目标。

## 明确对 Agent 可见的值

每个模块的 **Agent visible** 开关是一项披露决定。启用后，`items_search` 包含该模块的 `value`，此值可能进入 Agent 上下文及模型提供方日志。TOTP 模块可见时，OpenKeylet 只返回当前六位验证码，绝不返回永久 TOTP 种子。

需要留在 Agent 上下文之外的值，不应启用 Agent 可见性。该开关与模块能否被 OpenKeylet 用于填写、SSH 或 API 操作是独立的。

## OpenKeylet 不防御的情况

OpenKeylet 不是沙箱、策略引擎、DLP 系统或授权服务器，不能防御：

- 恶意、已被攻破或遭提示词注入的 Agent（见下文）；
- 以同一操作系统用户身份运行的其他进程；
- 已被攻破的浏览器、扩展、终端、远端主机或操作系统；
- Agent 聚焦了错误的桌面/浏览器控件；
- 命令或远端服务新产生的敏感数据；
- 所请求目标或操作本身不安全的任务。

隐藏模块不经 `items_search` 返回、对输出进行脱敏，这两项只防止正常使用中的意外泄露；它们不是针对恶意 Agent 或执行被注入指令的 Agent 的安全边界。OpenKeylet 不提供 `get_secret` 工具，但任何已启用条目的秘密都可以被替换进输出由 Agent 掌控的 `terminal_run`、`ssh_run` 或托管终端命令；在条目未保存服务 URL 或网址规则时由 `http_send` 发送到任意目标；或由 `secret_write_file` 渲染到 Agent 随后能用自身工具读取的文件中。输出脱敏只匹配原值及上文列出的常见编码，因此以其他方式变换秘密的命令（例如反转或拆分）会返回未脱敏的值。条目的 **启用** 开关才是授权闸门：任何已启用条目都可被连接到 OpenKeylet 的任意 Agent 使用。

MCP 工具注解只是描述性提示。OpenKeylet 在 Rust 后端执行实际限制，绝不把注解或提示词指令当作授权。

## 操作边界

OpenKeylet 的 MCP 工具，尤其是 `terminal_*`、`ssh_*`、`http_send` 和 `secret_write_file`，以桌面用户的权限在 OpenKeylet 进程内运行。它们不受 Agent 客户端对自身 shell 施加的任何沙箱或命令审批机制约束，且即使不涉及任何条目，`terminal_run` 也能执行。请在 Agent 客户端中为这些工具保留逐次审批，不要一键放行整个 OpenKeylet 服务。

### 浏览器与桌面填写

扩展弹窗在条目未设置专门网址规则时按协议、主机和端口精确匹配。多网址规则支持主域名、主机、完整网址、前缀、正则及“不匹配”；常规规则保留已保存的协议和端口，前缀规则还要求同源，正则规则拒绝远程 HTTP。规则作用于聚焦 frame 的地址，写入时再次校验；跨域 frame 会被拒绝。弹窗仅在用户明确操作后保存，并共享本机密码库，不在扩展存储中缓存密码。已配置的所有者 PIN 同样保护弹窗访问；每次在扩展窗口中确认的 Passkey 操作都会重新验证 PIN。配对时固定扩展 Origin，每个 WebSocket 连接都必须持有配对令牌。网页内容不能选择密码库 RPC 方法。由人工完成的 Passkey 请求通过独立的扩展 Origin 确认窗口进行，依据页面 Origin 和公共后缀列表校验 RP ID，仅在 PIN 验证成功后设置 UV 标志。私钥不会进入网页脚本、扩展存储或 Agent 可读字段。以同一操作系统用户身份运行的本地进程不在此保护边界内。

Agent 的 Passkey 请求走另一条路径。**允许 Agent 使用 Passkey**（系统 → WEB / 04）**默认关闭**，在所有者显式开启前 `browser_passkey` 会直接拒绝。开启后，`browser_passkey` 仅在 Agent 预先挂载拦截并由其触发网页 WebAuthn 请求时，为已启用条目完成登录或注册，不打开确认窗口也不要求输入 PIN，签名的认证器数据基于所有者的长期授权同时声明用户在场（UP）与用户验证（UV）。`browser_passkey` 拒绝接管或完成已在人工确认窗口中等待的请求。RP ID 仍会依据页面 Origin 校验。关闭该设置后 `browser_passkey` 将直接失败，恢复为仅能手动确认。

可关闭的保存提示只在真实用户交互后、浏览器产生表单提交事件时读取可见登录字段，不逐键采集内容。这是便捷识别规则，不能证明网站可信或认证成功。仅接受与顶层标签页同源的 HTTPS／本机页面，来源网址取自 Chrome 提供的消息发送者信息。待保存信息仅在插件后台内存中保留，最多十个标签页、五分钟，不写入扩展存储，也不发送到外部服务。跨来源跳转、关闭标签页、连接断开、关闭提示、忽略或在插件中主动锁定时清除。只有可信扩展页面完成已配置的 PIN 解锁后才能读取和确认保存，更新时检查条目版本；网页消息不能读取或保存凭据。网页提示不含采集的字段内容。密码库解锁时，已有账号比较仅在本机完成；浏览器或后台重启可能丢弃尚未保存的建议。

`credential_fill` 向当前聚焦控件写入一个值。调用方设置 `submit=true` 时，OpenKeylet 还会提交聚焦浏览器表单，或在桌面/托管终端目标按 Enter。桌面填写依赖真实操作系统前台焦点，仅有后台 DOM 焦点不够。OpenKeylet 无法证明当前聚焦目标可信。

### 托管终端

每个 stdio MCP 会话中，OpenKeylet 记住最近选择的兼容项目和当前托管终端。唯一的 `items_search` 结果或明确指定的 item 会选中项目，后续填写、SSH、传输、HTTP 和终端操作可省略重复名称。`terminal_start` 或明确使用另一终端 ID 会选中当前终端，后续 write、read、fill、stop 可省略重复 UUID。PTY 也保留自己的项目绑定直到结束。这是对话便利状态，不是授权边界；已结束终端及被禁用、删除或不兼容项目会自动忽略。

OpenKeylet 不添加策略 shell。`terminal_run` 执行普通单次本地 shell 命令；需要交互进程时，`terminal_start` 打开所请求程序或原生 Windows 脚本。子进程继承 OpenKeylet 的普通用户环境，使已安装工具保持用户原有行为。`terminal_run` 可把调用方文本直接写入标准输入，避免 shell 插值和临时文件。它和 `terminal_start` 可在命令或工作目录中替换 `{{openkeylet:module}}`；单次 stdin、PTY 参数及后续 `terminal_write` 也支持相同的本地替换，`secretEnv` 可把选定模块注入子进程环境。`terminal_write` 可按 Enter；除非调用方指定截止时间，`terminal_read` 可等待目标标记而不受 OpenKeylet 截止时间限制。这些值及常见编码会从返回输出中脱敏。本地命令和普通终端输入可能影响本地或外部系统。脱敏覆盖“安全目标”一节所述的值，即使其中夹杂 CR/LF、行编辑器换行或 ANSI 转义序列；但不覆盖无关环境变量或进程可能打印的每一种秘密。托管终端启动时设置 `HISTFILE=/dev/null` 与 `fish_private_mode=1`，默认 PowerShell 会被设置为不保存 PSReadLine 历史，因此带有替换秘密的命令不会写入 shell 历史，除非用户的 shell 配置自行设定历史文件。`browser_inspect` 会去掉所列标签页 URL 的 query 和 fragment，并遮盖被检查页面 URL 中的 query 值。每次 `terminal_run`、`terminal_start` 和 `terminal_write` 调用都会记入活动记录，包括不使用任何条目的调用；记录不包含命令或输入文本。

### SSH

保存了密码或私钥的 item 可授予 Agent 完整 SSH 命令执行和递归 SFTP 文件/目录传输能力。主机、端口和用户名可保存为默认值，也可由 Agent 在当前调用指定；两种来源均无端口时使用 22。`ssh_run` 可将调用方文本直接写入远端进程标准输入，并在 stdin、命令或工作目录中替换 `{{openkeylet:module}}`。`secretEnv` 可向远端环境注入其他已存模块。OpenKeylet 会从返回输出中脱敏这些值。Agent 按用户任务选择上传/下载路径；默认在准备好完整临时副本后替换现有目标，包括文件转目录或目录转文件。OpenKeylet 没有 observation、diagnostic、restricted 或 execution 模式。

首次连接某个主机和端口时，服务器出示的主机密钥会被固定在数据目录中仅限本机的 `ssh-known-hosts.json` 文件里，该文件不会同步或导出。之后连接同一主机和端口必须出示相同密钥：不一致时在发送任何凭据之前拒绝连接，且没有任何 MCP 工具可以重置固定记录。所有者可用 `openkeylet ssh hosts` 列出固定记录，用 `openkeylet ssh forget-host <host> [--port <port>]` 重置其中一条；已配置所有者 PIN 时会要求输入 PIN。固定主机密钥防御的是冒充服务器的网络攻击者；与数据目录中的所有文件一样，固定记录仅受操作系统账号保护，因此拥有本机 shell 权限的进程或 Agent 可以删除固定记录。首次使用仍属于首次信任（TOFU）：首次连接看到的密钥未经验证即被接受；由于 Agent 可以在运行时提供主机，它仍可把凭据发往一个新主机，该主机会在首次使用时被固定。

### API 请求

任何启用且配置了秘密的 item 都可用作 HTTP 请求上下文。保存服务 URL 时，调用方可省略请求 URL 使用该值，或提供相对路径。来自已保存服务 URL 或网址规则的条目的秘密，无论是作为认证自动注入，还是通过 `{{openkeylet:module}}` 占位符、跨条目 `{{openkeylet:Item/module}}` 占位符或 `secretBindings` 引用，都只会发送到与该条目保存 URL 同源的地址，或匹配该条目某条网址规则的 URL（如果网址规则显式作用于服务 URL 自身 Origin，例如 `never`、`exact` 或 `prefix` 规则，则以这些规则为准，不再按同源兜底放行）；其他目标会在发送任何内容之前被拒绝。既没有保存 URL 也没有网址规则的条目不受绑定：由 Agent 提供绝对 HTTP/HTTPS URL，也就由 Agent 决定其秘密发往何处。该绑定只适用于 `http_send`；`terminal_run`、`ssh_run`、托管终端输入和 `secret_write_file` 中使用的占位符不绑定任何目标。

对于内置 API 凭据或 Basic 组合未覆盖的认证方式，`{{openkeylet:password}}` 或 `{{openkeylet:service token}}` 等占位符直接解析所指模块，在 URL、header、query、JSON/文本 body 或 form 值中本地替换。`http_send.secretBindings` 仅在占位符名与模块名不同时作为可选别名映射。解析值加入响应和活动脱敏，不返回给调用方；TOTP 绑定使用当前验证码，而非保存的种子。

OpenKeylet 跟随 HTTP/HTTPS 重定向，直到服务停止重定向或达到调用方可选超时；`followRedirects=false` 时改为返回 3xx 响应。重定向到其他 Origin 时，OpenKeylet 会剥离它提供的凭据，且包含秘密的请求体绝不会重新发送到其他 Origin。调用方可发送普通 header、cookie、`Host` 或自己的认证值；只有 OpenKeylet 为已存凭据注入的 header 受 OpenKeylet 控制。默认情况下 `http_send` 正常返回脱敏后的响应，以保证日常 API 调用无缝快速；仅脱敏 OpenKeylet 已知秘密值，调用签发新令牌/密钥的接口时可通过 `captureSecrets` 直接存库（若返回结构未知可传 `holdResponse=true`，再通过 `http_save_secret` 从加密本地回执中提取）。只要有一个 `captureSecrets` 路径未匹配，或响应体不是 JSON，响应体和响应头会被扣留在加密本地回执中（单次最多 1 MiB，每会话保留最近 8 份 / 5 分钟），只返回 `responseId`、候选编号 `candidates` 与 `jsonPaths`，从而无需重复发请求即可完成保存。同理，`browser_save_key` 与 `browser_save_login` 允许由已配对扩展直接把网页展示的 API Key 或刚提交的登录存入本地库，明文不经过 MCP 上下文。活动记录包含 HTTP 方法、Origin 和不含 query 的路径，已知已存秘密在保存活动前脱敏。

调用方提供路径时，`http_send` 可上传本地文件或把响应保存到本地。OpenKeylet 不独立判断用户请求的本地文件是否适合发送、应发送给哪个 HTTP/HTTPS 目标，或明确请求的响应应存在哪里。默认替换现有响应文件，调用方可明确关闭替换。

## 本地数据与备份

Vault（`vault.json`）保存在当前用户的应用数据目录（`…/mcp-vault/v2`）。默认模式下，256 位 Vault 密钥保存在数据目录之外：优先使用操作系统凭据存储（Windows 凭据管理器或 Linux Secret Service），不可用或处于 macOS 时则存放在独立的用户密钥目录（Linux/Unix 为 `~/.config/openkeylet/master.key`，Windows 为 `%LOCALAPPDATA%\OpenKeylet\master.key`，macOS 为 `~/Library/Application Support/OpenKeylet/master.key`）。密钥文件及新建的密钥目录仅限当前用户访问（Unix 上为 `0600`/`0700`，Windows NTFS 上为禁用继承的仅当前用户+`SYSTEM` 受保护 DACL）。旧版留在数据目录内的 `<data_dir>/master.key` 会在验证可解开 `vault.json` 后保守迁移到外部目录，且旧位置永久保留为读取后备。显式指定数据目录（`OPENKEYLET_DATA_DIR`）时密钥仍保存在 `<data_dir>/master.key` 以保持便携自包含；任何模式下都可通过绝对路径环境变量 `OPENKEYLET_KEY_FILE` 指定独立密钥文件位置（并优先于默认位置与操作系统凭据存储）。**请注意：默认模式下单独拷贝数据目录不再等于完整备份密码库**（因为密钥不在目录内），正式备份请使用口令保护的 `.mvault` 导出或仓库同步。静态机密性仍取决于操作系统账号和全盘加密：能同时读取数据目录与该账号凭据存储或密钥目录的人即可解密 Vault。

只有每个条目的秘密包（密码、用户名、私钥、令牌、TOTP 种子、Passkey、银行卡/身份/安全笔记字段、密码历史和 Agent 备注）是加密的。条目名称、描述、文件夹、主机、端口、服务 URL、网址规则和自定义字段名以未加密形式保存在 `vault.json` 中；活动记录以未加密形式保存在数据目录中单独的本机文件 `activity.jsonl` 里，从不上传或导出。

PIN 用于保护 GUI 明文查看和扩展密码库访问，并为每次在扩展窗口中确认的 Passkey 操作提供验证；它不是独立加密密钥，也不能阻止以同一用户身份运行的其他进程。

桌面端和 CLI（`--passphrase`）新导出的 `.mvault` 使用用户提供的独立备份密码（≥12 位）、随机 128 位盐、Argon2id（64 MiB、3 次、1 并行）和 XChaCha20-Poly1305，附加认证数据绑定容器版本。文件不携带密码或解锁密钥；错误密码不会修改本地密码库。旧版及未使用口令的 CLI 自动解锁包仍包含解锁材料，应按包含明文秘密的文件保护。两种容器均可导入。

### 远程 Browser Bridge 与无头管理

Browser Bridge 默认只绑定 `127.0.0.1`。非回环绑定（`OPENKEYLET_BRIDGE_BIND`）在未通过 `OPENKEYLET_BRIDGE_ALLOW_LAN=1` 明确开启时会被拒绝；支持可选的客户端 IP/CIDR 允许列表（`OPENKEYLET_BRIDGE_ALLOW_IPS`）、可配置的扩展 Origin（`OPENKEYLET_BRIDGE_ALLOWED_ORIGINS`）、连接元数据日志（不含凭据值）、已连接客户端跟踪，以及配对令牌轮换（`openkeylet browser reset`）。即使在 LAN 模式下，内部 `/internal/*` 端点也会拒绝非本机对端。

可选的无头管理服务（`openkeylet admin serve`）默认关闭，严格绑定 `127.0.0.1:39273` 供 SSH 隧道访问（`ssh -L 39273:127.0.0.1:39273 user@server`），要求全新的 256 位 Bearer 令牌并提供轮换与撤销端点，默认隐藏秘密明文，已配置 PIN 时显式查看明文需先验证所有者 PIN。详见 [docs/HEADLESS_AND_REMOTE.md](docs/HEADLESS_AND_REMOTE.md)。

信用卡、身份和安全笔记字段存入原有加密秘密包，默认不向 Agent 显示，且不会独自启用通用 SSH/HTTP/Agent 填写能力。浏览器只有在已解锁且用户选择操作后才能读取这些字段。自动填写检查当前来源，只支持 HTTPS 与本机开发地址，忽略隐藏字段，不提交表单。

已删除项目加密保留在本机回收站中，直到用户永久删除；Agent、自动填写和 Passkey 签名无法使用回收站项目。最近 20 条旧密码保存在项目的加密秘密包内，仅限解锁后的所有者历史接口读取，也纳入已知秘密脱敏范围。恢复、永久删除及清除历史要求当前版本标记。完整导出和 GitHub 快照包含回收站和密码历史；本机删除不会清除已有备份。

## 可选 GitHub 加密快照

GitHub 备份使用独立的认证加密格式，不使用自解锁的 `.mvault` 容器。随机生成的 256 位同步密钥通过 XChaCha20-Poly1305 和绑定版本的附加认证数据加密完整便携数据。默认情况下，这把密钥存放在同一账号下的另一个私有仓库里（名称为密文仓库名加 `-key`），因此新设备只要绑定账号即可恢复，任何单个仓库都不同时持有密文和密钥。这种分开存放针对的是单个仓库外泄：被设为公开、被 fork 或克隆，或被只授权了该仓库的令牌访问。它不能防御控制了账号的人、能同时读取两个仓库的令牌，或托管服务方；这些情况下密码库都可被读取。连接已有备份时由所有者手动填入的密钥会被直接使用，不会上传。仓库访问令牌从不上传。绑定仓库不会改变本机密码库的加密或解锁方式：同步密钥和访问令牌保存在本机的 `github-backup.json` 中，用本机 Vault 密钥加密。本机秘密的序列化缓冲区在使用后清零。

账号检查仅扫描当前账号下 `private: true` 的私有仓库（通过 `openkeylet-vault` Topic 与 `openkeylet.vault.json` 密文信封头精准识别，无需解密），可自动定位已有的 OpenKeylet 私有密码仓。用户明确选择后，通过隐藏、有输出限制与超时的子进程读取本机 GitHub CLI 授权，令牌不会返回渲染界面。只允许在已验证的当前账号下创建私有仓库，并始终请求私有可见性；钥匙仓库在不存在时自动创建，密文仓库仅在所有者要求时创建；不会自动重命名已有仓库或将其改为私有。首份上传是设置流程中的显式选项，沿用加密快照和并发冲突检查。

客户端只连接 GitHub.com API，或在使用自建 Gitea / Forgejo 时只连接所有者配置的 HTTPS 服务器；不跟随重定向，限制响应和快照大小，不回显远端错误正文。上传、同步、恢复及查看历史前都会检查密文仓库的身份、默认分支与私有可见性，同时校验配对的钥匙仓库未被改为公开；写入使用此前确认的文件 SHA，冲突或结果不确定时不强制重试。这些检查不能阻止仓库所有者之后公开、删除仓库，或在两次 API 调用之间修改仓库。认证加密保护内容完整性和机密性，不保证远端可用性；当前手动备份格式也不对恶意仓库操作者提供密码学层面的防回滚保证。

恢复采用事务式合并，不删除或覆盖本机项目。Git 历史会保留过去的密文。断开不会清除远端备份、其他克隆、撤销令牌或轮换同步密钥。取得同步密钥及任意快照的人可以解密该快照，Git 历史会保留这两者。同一系统用户被攻陷仍不在保护范围内。删除钥匙仓库后，除非仍有已连接的设备或离线保存的密钥副本，否则快照无法再读取；OpenKeylet 无法重置密钥。

## 基于 GitHub Releases 的签名自动更新

OpenKeylet 直接通过 GitHub Releases 的固定地址（`https://github.com/omaekumiko2-create/OpenKeylet/releases/latest/download/latest.json`）检查更新，不依赖自有域名或第三方中转服务器。官方发行版在编译期内置 32 字节 Ed25519 公钥，强制校验更新清单的域分离 Ed25519 签名（`openkeylet-update-v1\n<payload>`）、安装包精确字节数与 SHA-256 哈希、GitHub Releases HTTPS 域名白名单（含重定向校验）、SemVer 防降级、压缩包路径穿越/软链接拦截，并在 macOS 上验证 `codesign --verify --deep --strict` 后才允许原地替换程序文件。未内置发布公钥的本地自编译版本禁止自动安装。配置 PIN 锁时，安装更新或修改更新偏好均需先完成所有者解锁。

## 漏洞报告

通过 GitHub Security Advisories 私密报告疑似漏洞。不要包含真实凭据、Vault 文件、备份、主密钥文件、API 响应、终端输出或敏感本地路径。

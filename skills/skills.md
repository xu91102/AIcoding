### 浅谈一下 claude 的 skills

# 为什么需要 skills，skills 解决了什么问题

1.我们都知道模型是有一个上下文限制的大约 200k 我们使用的 mcp 什么的是非常吃 token 的，你要让这个 AI 理解和使用这个 mcp 需要写提示词 propmt 是干什么用的 如何使用以及调用示例，这就导致我们在使用 AIcoding 的时候明明 200k 的上下午对话了几次就占满了，首当其冲就是 mcp，导致消耗 token 和费用都很高，skills 的出现就是来解决这一痛点的，是因为它解决了一个很具体真实的痛点：**Claude 容易出现健忘、需重复写提示词、太费 token！**

过去使用  Claude  最大的痛点是 “健忘”：

每换一个任务、每开一次对话，都要重复一堆东西。

Skills  出现后，这些都能收纳成一个说明书。把规则提前写好，模型只需要看到有这么个规则，大概 100 个 token，需要用到的时候再打开看。

# skills 感觉和 claude.md 很像？

很多人看到  Skills  的功能介绍，第一印象会觉得：“**这不就是自定义提示吗？这不就是 claude 的 ruel 文件吗？** ”

其实不一样。

自定义提示只是一次性的说明，且无法文件化、资产化复用；

而  Skills  是可以**保存、调用、组合、反复优化的体系化工作规范文件。**

说白了，Skills 就是一套你写给 Claude 的 “说明书” 和 “SOP（标准作业程序）
从功能用途来看，Skills 和 CLAUDE.md 的功能咋一看有很多相似之处，但如果深究一下的话，他们两者之间还是有本质上区别。

#### 1、Claude Skills（技能）

`Skills`  通常指的是封装好的特定功能或任务模块。你可以把它们理解为 “插件” 或 “宏”。它们旨在让 Claude 执行具体的、重复性的操作。

> 例如，定义一个 “代码审查员” 技能，当用户触发时，Claude 会严格根据这个技能中定义的规则（比如检查安全性、性能）来运行。

通常不是单一的文件，而是一个**目录结构**，包含指令 + 脚本 + 资源，Skills 的目录结构可以很丰富，除了主文件 SKILL.md，还可以包含检查清单、参考文档、辅助脚本等：

```
my-skill/
├── SKILL.md (required)
├── reference.md (optional documentation)
├── examples.md (optional examples)
├── scripts/
│   └── helper.py (optional utility)
└── templates/
    └── template.txt (optional template)
```

且 Claude 只会读取 Skill 的简短说明，只有在真正需要使用时才会加载完整内容，不会一开始就占用大量上下文。

需要额外说明一点，Skills 技能核心是`SKILL.md`文件，且必须包含 YAML 头信息，示例如下：

```
---
名称: 生成提交消息
描述: 根据 git 差异生成清晰的提交消息。在编写提交消息或审查暂存更改时使用。
---

# 生成提交消息

## 指令

1. 运行 `git diff --staged` 查看更改
2. 我将提供包含以下内容的提交消息：
   - 不超过 50 字符的摘要
   - 详细描述
   - 受影响的组件

## 最佳实践

- 使用现在时
- 解释内容和原因，而非方式
```

这也是`Skills`和`MCP`、`FunctionCaling`的区别，它可以实现分层加载，给上下文窗口减负。启动时，只加载 YAML 头配置（包含 name，description），大概也就 100 个 token。Skills 真正的触发时机，是通过自然语言触发，Claude 会根据你的任务描述自动判断是否需要调用某个 Skill。任务触发时，才会读取整个 Skill.md 正文内容。

#### 2、CLAUDE.md 文件

`CLAUDE.md`是项目 / 全局的静态上下文配置文件，本质上就是一个静态的 Markdown 文件。

当 Claude (例如通过 Claude for VS Code 插件或 MCP) 读取你的项目时，它会优先查找这个文件，以了解该项目的整体背景、代码风格、开发规范等。通常包含项目介绍、架构说明、编码约定等非执行性的背景信息。

> 就像新员工入职时拿到的 “员工手册” 或 “项目文档”，用来阅读和理解，而不是直接执行的命令。

该文件在启动就会全量加载到上下文，且持续生效（自动加载，无需触发），内容越长消耗上下文 token 也会越多，一般不建议写太多内容。

**内容建议**：统一团队代码风格、传递项目架构、固化开发流程、架构说明、提交规则等

**一句话小结**，如果你想让 Claude  **“学会做某件具体的活”** ，你需要配置  **Skills**；如果你想让 Claude  **“了解你的项目情况”** ，你需要编写  **CLAUDE.md**。

### Skills vs MCP  有什么区别？

很多人刚接触 Skills 时，会和 MCP 傻傻分不清，那么 Skills 和 MCP 之间到底有什么区别呢？

首先，MCP 是一个开源协议，用于连接 AI 和外部系统，AI+MCP，你就可以调用各种外部工具。

> 比如你可以让 Claude 访问数据库、API、文件系统、消息系统等外部资源。像常用的 Playwright MCP，就是让 Claude 能够操作浏览器。

如果，把 Claude  比喻 “头脑”，MCP  是它能调用的工具，而 Skills  则规定它的做事方法。

**一句话小结**：MCP 是教 AI 大模型怎么连接外部系统、API。Skills 是教 AI 大模型怎么用工具，按什么流程处理，输出什么格式。

# ### Claude Skills 有哪些类型，从哪里查找？

#### Skills 的类型

| 类型                | 说明                      | 示例              |
| ------------------- | ------------------------- | ----------------- |
| **User Skills**     | 用户自定义技能,存储在本地 | 个人工作流自动化  |
| **Plugin Skills**   | 插件提供的技能,随插件安装 | frontend-design   |
| **Built-in Skills** | Claude Code 内置技能      | commit, review-pr |

#### 常用官方 Skills

```
# 前端设计技能
npx skills-installer install @anthropics/claude-code/frontend-design --client claude-code

# 文档协同技能
npx skills-installer install @anthropics/claude-code/doc-coauthoring --client claude-code

# Canvas 设计技能
npx skills-installer install @anthropics/claude-code/canvas-design --client claude-code

# PDF 处理技能
npx skills-installer install @anthropics/claude-code/pdf --client claude-code

# 算法艺术生成
npx skills-installer install @anthropics/claude-code/algorithmic-art --client claude-code
```

#### 如何使用 Skills

**查看可用 Skills:**

```
claude /skills
```

**调用 Skill:**

```
# 在 Claude Code 对话中
使用 frontend-design skill 优化 https://example.com

使用 pdf skill 提取 report.pdf 中的表格数据
```

**Skill 目录结构:**

```
my-skill/
├── skill.json          # Skill 元数据
├── skill.md            # Skill 文档
├── api/                # API 定义(可选)
└── tools/              # 自定义工具(可选)
```

`**skill.md 示例:**

```
# xxx Skill

这个技能帮助用户快速完成[特定任务]。

## 使用场景

- 场景1:描述...
- 场景2:描述...

## 使用方式

用户只需要告诉你要完成什么,这个技能就会自动:

1. 分析需求
2. 执行步骤
3. 返回结果

## 注意事项

- 注意事项1
- 注意事项2
```

**安装本地 Skill:**

```
# 将技能复制到 Claude Code 配置目录
cp -r my-skill ~/.claude/skills/

# 或使用安装命令
npx skills-installer install ./my-skill --client claude-code
```

## 实用技巧与快捷操作

### 基础操作技巧

#### 项目初始化(/init)

```
# 自动生成 CLAUDE.md
/init

# 或手动指定
claude /init "这是一个 Node.js + React 项目"
```

#### 快速引用上下文(@提及)

```
# 引用单个文件
@src/auth.ts

# 引用整个目录
@src/components/

# 引用多个文件
@src/auth.ts @src/user.ts @src/database.ts

# 引用 MCP 服务器
@mcp:github

# 模糊匹配
@auth  # 自动匹配 auth.ts, auth.controller.ts 等
```

#### 核心命令速查

```
# 基础操作
claude                    # 启动 Claude Code
claude -p "prompt"        # Headless 模式
claude --version          # 查看版本

# 斜杠命令
/clear                    # 清空对话
/compact                  # 压缩对话
/context                  # 查看上下文
/cost                     # 查看费用
/model                    # 切换模型
/mcp                      # 管理 MCP
/skills                   # 查看 Skills
/hooks                    # 管理 Hooks
/agents                   # 管理子代理
/status                   # 系统状态
/doctor                   # 诊断环境

# 快捷键
Ctrl+R                    # 搜索历史
Ctrl+S                    # 暂存提示词
Ctrl+C                    # 中止操作
Shift+Tab × 2             # Plan 模式
ESC ESC                   # 回退操作
Alt+V                     # 粘贴图片

# 文件操作
@file.ts                  # 引用文件
@src/                     # 引用目录
```

### 项目组织最佳实践

#### 目录结构规范

```
project/
├── .claude/                    # Claude Code 配置
│   ├── settings.json           # 项目级设置
│   ├── agents.json             # 子代理配置
│   ├── rules/                  # 模块化规则
│   │   ├── auth.md
│   │   ├── database.md
│   │   └── api.md
│   └── mcp.json                # MCP 配置
├── src/                        # 源代码
├── tests/                      # 测试代码
├── docs/                       # 文档
├── CLAUDE.md                   # 项目主配置
└── README.md                   # 项目说明
```

| 配置文件          | 位置                       | 作用           |
| ----------------- | -------------------------- | -------------- |
| **CLAUDE.md**     | 项目根目录                 | 项目配置       |
| **settings.json** | ~/.claude/ 或项目/.claude/ | 全局/项目设置  |
| **agents.json**   | ~/.claude/ 或项目/.claude/ | 子代理配置     |
| **mcp.json**      | ~/.claude/                 | MCP 服务器配置 |
| **hooks/**        | ~/.claude/hooks/           | Hook 脚本      |
| **skills/**       | ~/.claude/skills/          | 自定义 Skills  |
| **rules/**        | 项目/.claude/rules/        | 模块化规则     |

1. 并行处理是效率倍增的关键

同时运行 5 个终端实例 + 5-10 个网页会话
利用系统通知和多设备协作
效率提升可达 1900%+
2. AI 进化机制让工具越用越聪明

在 PR 评论中直接 @claude 反馈
自动将教训写入 CLAUDE.md
整个团队的 AI 助手持续进化
3. 验证闭环是质量保证的基石

永远给 Claude 验证自己工作的方法
代码质量提升 2-3 倍
返工率降低到 5%
4. 选择合适的工具

简单任务: Haiku 4.5 或国产模型
日常开发: Sonnet 4.5
复杂任务: Opus 4.5 + Thinking(创始人首选)
追求极致效率:聪明的大模型比"快但笨"的小模型更快
5. 先规划后执行

90% 的时间使用 Plan 模式
你是架构师,Claude 是执行者
一次做对,永远比反复修改更省时间

###   推荐资源

#### 官方资源

- **Claude Code 官网:**  [https://code.claude.com](https://code.claude.com/)
- **文档:**  <https://code.claude.com/docs>
- **GitHub:**  <https://github.com/anthropics/claude-code>
- **Skills 库:**  <https://github.com/anthropics/skills>
- **MCP 服务器:**  <https://github.com/modelcontextprotocol>

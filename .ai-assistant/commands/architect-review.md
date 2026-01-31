---
name: architect-review
description: 系统架构审查命令，全面评估系统设计的合理性和可扩展性
platform: universal
---

# 系统架构审查命令

对系统架构进行全面的专业评估，识别设计问题并提供改进建议。

## 使用方法

### Claude 用户
```markdown
请执行系统架构审查：

按照 .ai-assistant/commands/architect-review.md 的流程，
调用 .ai-assistant/agents/senior-architect.md 的专业能力，
应用 .ai-assistant/rules/architecture-principles.md 的设计原则，
对当前系统进行全面的架构评估。
```

### ChatGPT 用户
```markdown
请进行系统架构审查：

## 审查范围
- 整体架构设计
- 组件职责划分
- 数据流和控制流
- 可扩展性和性能
- 安全性和可维护性

## 输出要求
- 架构优势分析
- 问题识别和风险评估
- 具体改进建议
- 实施优先级排序
```

## 审查维度

### 1. 架构设计质量 (30%)
```
📋 设计原则遵循
├── SOLID 原则应用
├── 分层架构清晰度
├── 模块化程度
├── 接口设计合理性
└── 依赖关系管理

🎯 设计模式应用
├── 适当的设计模式选择
├── 模式实现正确性
├── 模式组合合理性
└── 反模式识别
```

### 2. 可扩展性评估 (25%)
```
📈 水平扩展能力
├── 无状态设计
├── 负载均衡支持
├── 数据分片策略
└── 缓存架构

📊 垂直扩展能力
├── 资源利用效率
├── 性能瓶颈识别
├── 优化空间评估
└── 硬件适配性
```

### 3. 可维护性分析 (20%)
```
🔧 代码组织结构
├── 目录结构合理性
├── 模块边界清晰度
├── 代码复用程度
└── 文档完整性

🛠️ 开发友好性
├── 本地开发环境
├── 调试便利性
├── 测试覆盖率
└── 部署自动化
```

### 4. 性能和可靠性 (15%)
```
⚡ 性能设计
├── 响应时间优化
├── 吞吐量设计
├── 资源使用效率
└── 性能监控

🛡️ 可靠性保障
├── 故障容错机制
├── 数据一致性
├── 备份恢复策略
└── 监控告警体系
```

### 5. 安全性检查 (10%)
```
🔒 安全架构
├── 认证授权机制
├── 数据加密传输
├── 输入验证防护
└── 安全日志审计
```

## 审查流程

### 阶段 1：架构概览分析
```markdown
## 1.1 系统边界识别
- **核心业务域**：主要业务功能和边界
- **外部依赖**：第三方服务和系统集成
- **数据流向**：数据的输入、处理、输出路径
- **用户角色**：不同用户类型和权限模型

## 1.2 技术栈评估
- **前端技术**：框架选择和架构模式
- **后端技术**：服务架构和技术选型
- **数据存储**：数据库选择和数据模型
- **基础设施**：部署环境和运维工具

## 1.3 架构风格识别
- **单体 vs 微服务**：架构风格适配性
- **同步 vs 异步**：通信模式合理性
- **集中 vs 分布式**：数据和服务分布策略
```

### 阶段 2：详细设计审查
```markdown
## 2.1 组件设计审查
### 前端组件架构
- **组件层次结构**：组件树的合理性
- **状态管理**：状态流转和数据共享
- **路由设计**：页面导航和权限控制
- **性能优化**：懒加载、缓存、虚拟化

### 后端服务架构
- **服务边界**：服务职责和边界划分
- **API 设计**：接口规范和版本管理
- **业务逻辑**：领域模型和业务规则
- **数据访问**：数据层抽象和优化

### 数据架构设计
- **数据模型**：实体关系和数据结构
- **存储策略**：读写分离、分库分表
- **缓存设计**：多级缓存和失效策略
- **数据一致性**：事务管理和最终一致性
```

### 阶段 3：非功能性需求评估
```markdown
## 3.1 性能需求评估
- **响应时间**：各接口的性能指标
- **并发处理**：系统并发能力评估
- **资源消耗**：CPU、内存、存储使用
- **扩展性**：负载增长的应对能力

## 3.2 可靠性需求评估
- **可用性**：系统可用性目标和实现
- **容错性**：故障处理和恢复机制
- **数据完整性**：数据保护和备份策略
- **监控体系**：健康检查和告警机制

## 3.3 安全需求评估
- **身份认证**：用户身份验证机制
- **访问控制**：权限管理和授权策略
- **数据保护**：敏感数据加密和脱敏
- **安全审计**：操作日志和安全监控
```

## 输出格式

### 架构审查报告
```markdown
# 🏗️ 系统架构审查报告

**项目名称**: 用户管理系统
**审查时间**: 2026-02-01
**审查范围**: 完整系统架构
**审查等级**: A- (85/100)

---

## 📊 审查概览

| 维度 | 评分 | 权重 | 加权得分 | 状态 |
|------|------|------|----------|------|
| **架构设计质量** | 88/100 | 30% | 26.4 | ✅ 优秀 |
| **可扩展性** | 82/100 | 25% | 20.5 | ✅ 良好 |
| **可维护性** | 85/100 | 20% | 17.0 | ✅ 良好 |
| **性能可靠性** | 80/100 | 15% | 12.0 | ⚠️ 一般 |
| **安全性** | 90/100 | 10% | 9.0 | ✅ 优秀 |
| **总分** | **85/100** | 100% | **85.0** | ✅ 良好 |

---

## ✅ 架构优势

### 1. 设计原则应用良好
- **分层架构清晰**：表现层、业务层、数据层职责明确
- **依赖注入完善**：使用 DI 容器管理依赖关系
- **接口抽象合理**：核心业务逻辑与实现细节分离

```typescript
// ✅ 优秀的分层设计示例
class UserController {
  constructor(private userService: UserService) {} // 依赖注入
  
  async createUser(req: Request): Promise<Response> {
    const result = await this.userService.createUser(req.body)
    return { success: true, data: result }
  }
}

class UserService {
  constructor(private userRepository: UserRepository) {}
  
  async createUser(userData: CreateUserData): Promise<User> {
    // 业务逻辑处理
    const user = new User(userData)
    return this.userRepository.save(user)
  }
}
```

### 2. 模块化程度高
- **功能模块独立**：用户、订单、支付模块边界清晰
- **代码复用良好**：公共组件和工具函数抽象合理
- **配置外部化**：环境配置和业务配置分离管理

### 3. 技术选型合适
- **前端技术栈**：React + TypeScript + Redux 适合复杂交互
- **后端技术栈**：Node.js + Express + TypeScript 开发效率高
- **数据存储**：PostgreSQL + Redis 满足业务需求

---

## ⚠️ 需要改进的问题

### 1. 性能优化空间 (中等优先级)

#### 问题：数据库查询效率低
**位置**: `UserService.getUsersWithProfiles()`
**问题描述**: 存在 N+1 查询问题，影响性能

```typescript
// ❌ 当前实现 - N+1 查询问题
async getUsersWithProfiles(): Promise<UserWithProfile[]> {
  const users = await this.userRepository.findAll()
  
  for (const user of users) {
    user.profile = await this.profileRepository.findByUserId(user.id) // N+1 问题
  }
  
  return users
}
```

**改进建议**:
```typescript
// ✅ 优化后实现 - 批量查询
async getUsersWithProfiles(): Promise<UserWithProfile[]> {
  const users = await this.userRepository.findAll()
  const userIds = users.map(u => u.id)
  const profiles = await this.profileRepository.findByUserIds(userIds)
  
  const profileMap = new Map(profiles.map(p => [p.userId, p]))
  return users.map(user => ({
    ...user,
    profile: profileMap.get(user.id)
  }))
}
```

**预期收益**: 查询时间减少 60-80%

#### 问题：缓存策略不完善
**位置**: 用户信息查询接口
**问题描述**: 频繁查询的用户信息未使用缓存

**改进建议**:
```typescript
// ✅ 添加缓存层
class CachedUserService {
  constructor(
    private userService: UserService,
    private cache: CacheService
  ) {}
  
  async getUserById(id: string): Promise<User | null> {
    const cacheKey = `user:${id}`
    
    // 尝试从缓存获取
    let user = await this.cache.get<User>(cacheKey)
    if (user) return user
    
    // 缓存未命中，从数据库获取
    user = await this.userService.getUserById(id)
    if (user) {
      await this.cache.set(cacheKey, user, 300) // 缓存5分钟
    }
    
    return user
  }
}
```

### 2. 可扩展性限制 (高优先级)

#### 问题：单体架构扩展瓶颈
**问题描述**: 随着业务增长，单体架构可能成为扩展瓶颈

**当前架构**:
```
┌─────────────────────────────────┐
│         单体应用                 │
│  ┌─────────┬─────────┬─────────┐ │
│  │ 用户模块 │ 订单模块 │ 支付模块 │ │
│  └─────────┴─────────┴─────────┘ │
│         共享数据库               │
└─────────────────────────────────┘
```

**建议架构演进**:
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   用户服务   │    │   订单服务   │    │   支付服务   │
│             │    │             │    │             │
│ ┌─────────┐ │    │ ┌─────────┐ │    │ ┌─────────┐ │
│ │ 用户DB  │ │    │ │ 订单DB  │ │    │ │ 支付DB  │ │
│ └─────────┘ │    │ └─────────┘ │    │ └─────────┘ │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                  ┌─────────▼───────┐
                  │    API 网关     │
                  │   服务发现      │
                  └─────────────────┘
```

**实施建议**:
1. **第一阶段**: 模块化重构，明确服务边界
2. **第二阶段**: 数据库分离，实现数据独立
3. **第三阶段**: 服务拆分，部署独立服务

#### 问题：数据库扩展性限制
**问题描述**: 单一数据库可能成为性能瓶颈

**改进建议**:
```typescript
// ✅ 读写分离配置
const databaseConfig = {
  master: {
    host: 'master-db.example.com',
    port: 5432,
    database: 'app_db',
    // 写操作配置
  },
  slaves: [
    {
      host: 'slave1-db.example.com',
      port: 5432,
      database: 'app_db',
      // 读操作配置
    },
    {
      host: 'slave2-db.example.com', 
      port: 5432,
      database: 'app_db',
      // 读操作配置
    }
  ]
}

class DatabaseService {
  async read(query: string, params: any[]): Promise<any> {
    const slave = this.selectSlave() // 负载均衡选择从库
    return slave.query(query, params)
  }
  
  async write(query: string, params: any[]): Promise<any> {
    return this.master.query(query, params) // 写操作使用主库
  }
}
```

### 3. 监控和可观测性不足 (中等优先级)

#### 问题：缺乏全链路监控
**问题描述**: 无法有效追踪请求在系统中的完整路径

**改进建议**:
```typescript
// ✅ 添加分布式追踪
import { trace, context } from '@opentelemetry/api'

class UserService {
  async createUser(userData: CreateUserData): Promise<User> {
    const span = trace.getActiveSpan()
    span?.setAttributes({
      'user.email': userData.email,
      'operation': 'create_user'
    })
    
    try {
      // 业务逻辑
      const user = await this.userRepository.save(new User(userData))
      
      span?.setStatus({ code: SpanStatusCode.OK })
      return user
    } catch (error) {
      span?.recordException(error)
      span?.setStatus({ 
        code: SpanStatusCode.ERROR, 
        message: error.message 
      })
      throw error
    }
  }
}
```

---

## ❌ 必须修复的问题

### 1. 安全漏洞 (紧急)

#### 问题：SQL 注入风险
**位置**: `UserRepository.findByEmail()`
**风险等级**: 🔴 高风险

```typescript
// ❌ 存在 SQL 注入风险
async findByEmail(email: string): Promise<User | null> {
  const query = `SELECT * FROM users WHERE email = '${email}'` // 危险！
  const result = await this.database.query(query)
  return result[0] || null
}
```

**修复方案**:
```typescript
// ✅ 使用参数化查询
async findByEmail(email: string): Promise<User | null> {
  const query = 'SELECT * FROM users WHERE email = ?'
  const result = await this.database.query(query, [email])
  return result[0] || null
}
```

**修复时限**: 立即修复

#### 问题：敏感信息泄露
**位置**: API 响应中包含密码哈希
**风险等级**: 🔴 高风险

**修复方案**:
```typescript
// ✅ 响应数据脱敏
class UserController {
  async getUser(req: Request): Promise<Response> {
    const user = await this.userService.getUserById(req.params.id)
    
    // 移除敏感字段
    const safeUser = {
      id: user.id,
      name: user.name,
      email: user.email,
      createdAt: user.createdAt
      // 不包含 password, passwordHash 等敏感字段
    }
    
    return { success: true, data: safeUser }
  }
}
```

---

## 🎯 改进优先级和实施计划

### 第一阶段：紧急修复 (1-2 周)
- [ ] **修复 SQL 注入漏洞** - 安全风险
- [ ] **移除敏感信息泄露** - 安全风险
- [ ] **添加输入验证** - 安全加固

### 第二阶段：性能优化 (3-4 周)
- [ ] **解决 N+1 查询问题** - 性能提升
- [ ] **实施缓存策略** - 响应时间优化
- [ ] **数据库索引优化** - 查询性能提升

### 第三阶段：架构演进 (2-3 个月)
- [ ] **模块化重构** - 为微服务做准备
- [ ] **数据库读写分离** - 扩展性提升
- [ ] **引入消息队列** - 异步处理能力

### 第四阶段：可观测性增强 (1 个月)
- [ ] **添加分布式追踪** - 问题定位能力
- [ ] **完善监控指标** - 系统健康度监控
- [ ] **建立告警体系** - 主动问题发现

---

## 📈 预期收益

### 性能提升
- **响应时间**: 平均响应时间减少 40-60%
- **并发能力**: 支持并发用户数提升 3-5 倍
- **资源利用**: CPU 和内存使用效率提升 30%

### 可维护性提升
- **开发效率**: 新功能开发时间减少 25%
- **Bug 修复**: 问题定位和修复时间减少 50%
- **代码质量**: 代码复杂度降低，可读性提升

### 可扩展性提升
- **水平扩展**: 支持无状态水平扩展
- **模块独立**: 支持独立开发和部署
- **技术演进**: 为微服务架构奠定基础

---

## 🔍 后续建议

### 定期架构审查
- **频率**: 每季度进行一次架构审查
- **范围**: 重点关注新增功能的架构影响
- **参与者**: 架构师、技术负责人、核心开发者

### 架构决策记录 (ADR)
- **建立 ADR 机制**: 记录重要的架构决策
- **决策追溯**: 便于理解历史决策的背景和原因
- **知识传承**: 帮助新团队成员理解架构演进

### 技术债务管理
- **债务识别**: 定期识别和评估技术债务
- **优先级排序**: 基于业务影响和修复成本排序
- **持续改进**: 在每个迭代中分配时间处理技术债务

---

*📋 注：本报告基于当前系统状态分析生成，建议结合业务发展规划制定具体的实施计划。*
*🔄 下次审查建议时间：2026-05-01*
```

## 命令参数

### 审查范围
```bash
/architect-review --scope=frontend
# 只审查前端架构

/architect-review --scope=backend  
# 只审查后端架构

/architect-review --scope=database
# 只审查数据架构
```

### 审查深度
```bash
/architect-review --depth=overview
# 概览级审查

/architect-review --depth=detailed
# 详细审查

/architect-review --depth=comprehensive
# 全面深度审查
```

### 输出格式
```bash
/architect-review --format=summary
# 输出摘要报告

/architect-review --format=detailed
# 输出详细报告

/architect-review --format=actionable
# 输出可执行的改进计划
```

## 集成建议

### 与其他命令集成
- `/code-review` - 结合代码审查验证架构实现
- `/security-audit` - 集成安全架构评估
- `/performance-check` - 验证性能架构设计

### 与开发流程集成
- **设计阶段**: 架构设计完成后进行审查
- **开发阶段**: 重大功能开发前进行影响评估
- **发布阶段**: 版本发布前进行架构健康检查

这个架构审查命令能够：
1. **全面评估**系统架构的各个维度
2. **识别问题**并提供具体的改进建议
3. **优先级排序**帮助团队合理安排改进工作
4. **持续改进**建立架构质量的持续提升机制
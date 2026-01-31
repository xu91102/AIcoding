---
name: code-review
description: 专业代码审查命令，全面评估代码质量、安全性和最佳实践
platform: universal
---

# 代码审查命令

对代码进行全面的专业审查，确保代码质量、安全性和可维护性。

## 使用方法

### Claude 用户
```markdown
请执行代码审查：

按照 .ai-assistant/commands/code-review.md 的标准，
调用 .ai-assistant/agents/code-reviewer.md 的专业能力，
应用 .ai-assistant/rules/coding-standards.md 的编码规范，
对指定的代码文件进行全面审查。

审查文件：[指定文件路径或代码片段]
```

### ChatGPT 用户
```markdown
请进行专业代码审查：

## 审查标准
- 代码质量和可读性
- 安全漏洞和风险
- 性能优化机会
- 最佳实践遵循
- 测试覆盖和质量

## 输出要求
- 问题分类和优先级
- 具体改进建议
- 代码示例对比
- 修复验证方法
```

## 审查标准

### 代码质量评分标准
| 等级 | 分数范围 | 标准描述 | 处理建议 |
|------|----------|----------|----------|
| **A** | 90-100 | 优秀，可作为团队标准 | 可直接合并 |
| **B** | 80-89 | 良好，小幅改进后可合并 | 建议改进后合并 |
| **C** | 70-79 | 一般，需要明显改进 | 必须改进后合并 |
| **D** | 60-69 | 较差，需要重大修改 | 重大修改后重审 |
| **F** | <60 | 不合格，需要重写 | 拒绝合并，重写 |

### 问题严重程度分类
| 级别 | 标识 | 处理要求 | 示例 |
|------|------|----------|------|
| **严重** | 🔴 | 必须修复才能合并 | 安全漏洞、逻辑错误 |
| **重要** | 🟡 | 强烈建议修复 | 性能问题、设计缺陷 |
| **一般** | 🟢 | 可选择性修复 | 代码风格、命名优化 |
| **建议** | 💡 | 改进建议 | 重构机会、最佳实践 |

## 审查维度

### 1. 代码质量 (40%)
```
📋 结构质量
├── 函数大小 (≤80 行)
├── 文件大小 (≤600 行)
├── 圈复杂度 (≤10)
├── 嵌套层级 (≤4 层)
└── 参数数量 (≤5 个)

🎯 设计质量
├── 单一职责原则
├── 开闭原则
├── 依赖倒置
├── 接口隔离
└── 里氏替换
```

### 2. 安全性 (25%)
```
🔒 输入验证
├── 用户输入校验
├── SQL 注入防护
├── XSS 攻击防护
├── CSRF 保护
└── 文件上传安全

🛡️ 数据保护
├── 敏感数据加密
├── 密码安全存储
├── API 密钥保护
├── 日志脱敏
└── 权限控制
```

### 3. 性能 (20%)
```
⚡ 算法效率
├── 时间复杂度分析
├── 空间复杂度分析
├── 数据结构选择
├── 算法优化
└── 缓存策略

🚀 系统性能
├── 数据库查询优化
├── 网络请求优化
├── 内存使用优化
├── 并发处理
└── 资源管理
```

### 4. 可维护性 (15%)
```
📚 代码可读性
├── 命名规范
├── 注释质量
├── 代码结构
├── 逻辑清晰度
└── 文档完整性

🔧 可扩展性
├── 模块化设计
├── 配置外部化
├── 接口抽象
├── 插件机制
└── 版本兼容性
```

## 审查流程

### 阶段 1：自动化检查
```bash
# 代码规范检查
eslint src/ --ext .ts,.tsx,.js,.jsx
prettier --check src/

# 类型检查
tsc --noEmit

# 测试覆盖率
npm run test:coverage

# 安全扫描
npm audit
snyk test

# 复杂度分析
complexity-report src/
```

### 阶段 2：结构分析
```markdown
## 文件结构检查
- [ ] 文件大小是否超过 600 行
- [ ] 目录组织是否合理
- [ ] 导入依赖是否清晰
- [ ] 模块职责是否单一

## 函数分析
- [ ] 函数长度是否合理 (≤80 行)
- [ ] 参数数量是否适当 (≤5 个)
- [ ] 返回值类型是否明确
- [ ] 副作用是否可控
```

### 阶段 3：逻辑审查
```markdown
## 业务逻辑
- [ ] 业务规则实现是否正确
- [ ] 边界条件处理是否完整
- [ ] 异常情况是否考虑
- [ ] 数据流转是否清晰

## 算法效率
- [ ] 算法复杂度是否合理
- [ ] 数据结构选择是否恰当
- [ ] 是否存在性能瓶颈
- [ ] 缓存策略是否有效
```

### 阶段 4：安全检查
```markdown
## 输入验证
- [ ] 用户输入是否充分验证
- [ ] SQL 查询是否使用参数化
- [ ] 文件操作是否安全
- [ ] API 调用是否有权限控制

## 数据保护
- [ ] 敏感数据是否加密存储
- [ ] 日志是否包含敏感信息
- [ ] 密钥是否硬编码
- [ ] 会话管理是否安全
```

## 输出格式

### 标准代码审查报告
```markdown
# 🔍 代码审查报告

**文件**: `src/services/UserService.ts`
**审查员**: Code Reviewer
**审查时间**: 2026-02-01 15:30:00
**代码行数**: 245 行
**总体评分**: B+ (83/100)

---

## 📊 评分详情

| 维度 | 评分 | 权重 | 加权得分 | 状态 |
|------|------|------|----------|------|
| **代码质量** | 85/100 | 40% | 34.0 | ✅ 良好 |
| **安全性** | 78/100 | 25% | 19.5 | ⚠️ 一般 |
| **性能** | 88/100 | 20% | 17.6 | ✅ 优秀 |
| **可维护性** | 80/100 | 15% | 12.0 | ✅ 良好 |
| **总分** | **83/100** | 100% | **83.1** | ✅ 良好 |

---

## ✅ 做得好的地方

### 1. 代码结构清晰
- **函数职责单一**：每个方法都有明确的单一职责
- **命名规范一致**：使用了清晰的驼峰命名法
- **类型定义完整**：TypeScript 类型使用规范

```typescript
// ✅ 优秀的函数设计
async createUser(userData: CreateUserData): Promise<User> {
  // 清晰的职责：创建用户
  const validationResult = this.validateUserData(userData)
  if (!validationResult.isValid) {
    throw new ValidationError(validationResult.errors)
  }
  
  const user = new User(userData)
  return this.userRepository.save(user)
}
```

### 2. 错误处理完善
- **异常类型明确**：使用了自定义异常类型
- **错误信息有用**：提供了具体的错误描述
- **异常传播合理**：适当的异常捕获和重新抛出

### 3. 测试覆盖良好
- **单元测试覆盖率**：达到 85%
- **测试用例完整**：覆盖了主要的业务场景
- **边界条件测试**：包含了异常情况的测试

---

## 🟡 需要改进 (建议修复)

### 1. 性能优化机会

#### 问题：N+1 查询问题
**位置**: `getUsersWithProfiles()` 方法 (第 156-168 行)
**严重程度**: 🟡 重要
**影响**: 查询性能随用户数量线性增长

```typescript
// ❌ 当前实现 - 存在 N+1 查询
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

**预期收益**: 查询时间减少 70-90%

#### 问题：缓存机会未利用
**位置**: `getUserById()` 方法 (第 45-52 行)
**严重程度**: 🟡 重要
**影响**: 频繁的数据库查询

**改进建议**:
```typescript
// ✅ 添加缓存层
async getUserById(id: string): Promise<User | null> {
  const cacheKey = `user:${id}`
  
  // 尝试从缓存获取
  let user = await this.cache.get<User>(cacheKey)
  if (user) {
    return user
  }
  
  // 缓存未命中，从数据库获取
  user = await this.userRepository.findById(id)
  if (user) {
    await this.cache.set(cacheKey, user, 300) // 缓存5分钟
  }
  
  return user
}
```

### 2. 代码重复问题

#### 问题：验证逻辑重复
**位置**: `createUser()` 和 `updateUser()` 方法
**严重程度**: 🟢 一般
**影响**: 代码维护成本增加

```typescript
// ❌ 重复的验证逻辑
async createUser(userData: CreateUserData): Promise<User> {
  // 重复的验证逻辑
  if (!userData.email || !userData.email.includes('@')) {
    throw new ValidationError('Invalid email')
  }
  if (!userData.name || userData.name.length < 2) {
    throw new ValidationError('Name too short')
  }
  // ...
}

async updateUser(id: string, userData: UpdateUserData): Promise<User> {
  // 相同的验证逻辑重复出现
  if (userData.email && !userData.email.includes('@')) {
    throw new ValidationError('Invalid email')
  }
  if (userData.name && userData.name.length < 2) {
    throw new ValidationError('Name too short')
  }
  // ...
}
```

**改进建议**:
```typescript
// ✅ 抽取公共验证逻辑
private validateUserData(userData: Partial<CreateUserData>): ValidationResult {
  const errors: string[] = []
  
  if (userData.email !== undefined) {
    if (!userData.email || !userData.email.includes('@')) {
      errors.push('Invalid email format')
    }
  }
  
  if (userData.name !== undefined) {
    if (!userData.name || userData.name.length < 2) {
      errors.push('Name must be at least 2 characters')
    }
  }
  
  return {
    isValid: errors.length === 0,
    errors
  }
}

async createUser(userData: CreateUserData): Promise<User> {
  const validation = this.validateUserData(userData)
  if (!validation.isValid) {
    throw new ValidationError(validation.errors)
  }
  // ...
}
```

---

## 🔴 必须修复 (阻塞合并)

### 1. 安全漏洞

#### 问题：SQL 注入风险
**位置**: `findUsersByQuery()` 方法 (第 89-95 行)
**严重程度**: 🔴 严重
**风险等级**: 高
**OWASP**: A03:2021 – Injection

```typescript
// ❌ 存在 SQL 注入风险
async findUsersByQuery(searchQuery: string): Promise<User[]> {
  const sql = `SELECT * FROM users WHERE name LIKE '%${searchQuery}%'` // 危险！
  return this.database.query(sql)
}
```

**攻击示例**:
```typescript
// 恶意输入可能导致数据泄露
const maliciousQuery = "'; DROP TABLE users; --"
await userService.findUsersByQuery(maliciousQuery)
// 生成的 SQL: SELECT * FROM users WHERE name LIKE '%'; DROP TABLE users; --%'
```

**修复方案**:
```typescript
// ✅ 使用参数化查询
async findUsersByQuery(searchQuery: string): Promise<User[]> {
  const sql = 'SELECT * FROM users WHERE name LIKE ?'
  const searchPattern = `%${searchQuery}%`
  return this.database.query(sql, [searchPattern])
}
```

**验证方法**:
```typescript
// 测试恶意输入
const testCases = [
  "'; DROP TABLE users; --",
  "' OR '1'='1",
  "' UNION SELECT * FROM admin_users --"
]

for (const testCase of testCases) {
  const result = await userService.findUsersByQuery(testCase)
  // 应该返回正常的搜索结果，而不是执行恶意 SQL
}
```

#### 问题：敏感信息泄露
**位置**: `getUserProfile()` 方法 (第 123-130 行)
**严重程度**: 🔴 严重
**风险等级**: 高
**OWASP**: A02:2021 – Cryptographic Failures

```typescript
// ❌ 返回了敏感信息
async getUserProfile(userId: string): Promise<UserProfile> {
  const user = await this.userRepository.findById(userId)
  return {
    ...user, // 包含了 passwordHash 等敏感字段
    profile: await this.profileRepository.findByUserId(userId)
  }
}
```

**修复方案**:
```typescript
// ✅ 过滤敏感字段
async getUserProfile(userId: string): Promise<UserProfile> {
  const user = await this.userRepository.findById(userId)
  const profile = await this.profileRepository.findByUserId(userId)
  
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    createdAt: user.createdAt,
    // 不包含 passwordHash, resetToken 等敏感字段
    profile
  }
}
```

### 2. 逻辑错误

#### 问题：并发更新竞态条件
**位置**: `updateUserBalance()` 方法 (第 178-185 行)
**严重程度**: 🔴 严重
**影响**: 可能导致数据不一致

```typescript
// ❌ 存在竞态条件
async updateUserBalance(userId: string, amount: number): Promise<User> {
  const user = await this.userRepository.findById(userId)
  user.balance += amount // 竞态条件：读取-修改-写入
  return this.userRepository.save(user)
}
```

**修复方案**:
```typescript
// ✅ 使用原子操作
async updateUserBalance(userId: string, amount: number): Promise<User> {
  return this.database.transaction(async (trx) => {
    const sql = 'UPDATE users SET balance = balance + ? WHERE id = ? RETURNING *'
    const result = await trx.query(sql, [amount, userId])
    return result[0]
  })
}
```

---

## 💡 改进建议

### 1. 架构优化

#### 建议：引入领域驱动设计
**当前问题**: 业务逻辑分散在服务层
**改进方向**: 使用领域模型封装业务规则

```typescript
// ✅ 领域模型示例
class User {
  constructor(
    private id: string,
    private name: string,
    private email: string,
    private balance: number
  ) {}
  
  // 业务规则封装在领域模型中
  updateBalance(amount: number): void {
    if (this.balance + amount < 0) {
      throw new InsufficientBalanceError('Insufficient balance')
    }
    this.balance += amount
  }
  
  changeEmail(newEmail: string): void {
    if (!this.isValidEmail(newEmail)) {
      throw new InvalidEmailError('Invalid email format')
    }
    this.email = newEmail
  }
  
  private isValidEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  }
}
```

#### 建议：实现仓储模式
**当前问题**: 数据访问逻辑与业务逻辑耦合
**改进方向**: 使用仓储模式抽象数据访问

```typescript
// ✅ 仓储接口
interface UserRepository {
  findById(id: string): Promise<User | null>
  findByEmail(email: string): Promise<User | null>
  save(user: User): Promise<User>
  delete(id: string): Promise<void>
}

// 具体实现
class DatabaseUserRepository implements UserRepository {
  async findById(id: string): Promise<User | null> {
    const row = await this.database.query('SELECT * FROM users WHERE id = ?', [id])
    return row ? this.mapToUser(row) : null
  }
  
  private mapToUser(row: any): User {
    return new User(row.id, row.name, row.email, row.balance)
  }
}
```

### 2. 测试改进

#### 建议：增加集成测试
**当前状态**: 主要是单元测试
**改进方向**: 添加 API 级别的集成测试

```typescript
// ✅ 集成测试示例
describe('User API Integration Tests', () => {
  it('should create user end-to-end', async () => {
    const userData = {
      name: 'John Doe',
      email: 'john@example.com'
    }
    
    const response = await request(app)
      .post('/api/users')
      .send(userData)
      .expect(201)
    
    expect(response.body.data).toMatchObject({
      name: userData.name,
      email: userData.email,
      id: expect.any(String)
    })
    
    // 验证数据库状态
    const savedUser = await database.users.findById(response.body.data.id)
    expect(savedUser).toBeTruthy()
  })
})
```

### 3. 监控和日志

#### 建议：添加结构化日志
**当前问题**: 缺乏有效的日志记录
**改进方向**: 实现结构化日志和监控

```typescript
// ✅ 结构化日志
class UserService {
  private logger = new Logger('UserService')
  
  async createUser(userData: CreateUserData): Promise<User> {
    this.logger.info('Creating user', {
      operation: 'create_user',
      email: userData.email,
      timestamp: new Date().toISOString()
    })
    
    try {
      const user = await this.userRepository.save(new User(userData))
      
      this.logger.info('User created successfully', {
        operation: 'create_user',
        userId: user.id,
        duration: Date.now() - startTime
      })
      
      return user
    } catch (error) {
      this.logger.error('Failed to create user', {
        operation: 'create_user',
        error: error.message,
        stack: error.stack
      })
      throw error
    }
  }
}
```

---

## 📋 修复清单

### 必须修复 (合并前)
- [ ] **修复 SQL 注入漏洞** - `findUsersByQuery()` 方法
- [ ] **移除敏感信息泄露** - `getUserProfile()` 方法  
- [ ] **解决并发竞态条件** - `updateUserBalance()` 方法
- [ ] **添加输入验证** - 所有公共方法

### 强烈建议修复 (本周内)
- [ ] **优化 N+1 查询** - `getUsersWithProfiles()` 方法
- [ ] **添加缓存层** - `getUserById()` 方法
- [ ] **抽取重复验证逻辑** - 创建公共验证方法
- [ ] **完善错误处理** - 统一异常处理机制

### 可选改进 (下个迭代)
- [ ] **引入领域驱动设计** - 重构业务逻辑
- [ ] **实现仓储模式** - 抽象数据访问层
- [ ] **增加集成测试** - 提升测试覆盖质量
- [ ] **添加结构化日志** - 改善可观测性

---

## 🎓 学习建议

### 推荐阅读
- **《Clean Code》** - Robert C. Martin
- **《Effective TypeScript》** - Dan Vanderkam  
- **《OWASP Top 10》** - Web 应用安全指南
- **《Domain-Driven Design》** - Eric Evans

### 技能提升
- **安全编程实践** - 学习常见安全漏洞和防护方法
- **性能优化技巧** - 掌握数据库查询和缓存优化
- **设计模式应用** - 在实际项目中应用设计模式
- **测试驱动开发** - 提升代码质量和测试覆盖率

---

*📝 注：本次审查基于静态代码分析和最佳实践标准，建议结合动态测试和业务需求进行综合评估。*
*🔄 建议修复完成后重新提交审查。*
```

## 命令参数

### 审查范围
```bash
/code-review --files=src/services/UserService.ts
# 审查指定文件

/code-review --changed-files
# 只审查变更的文件

/code-review --directory=src/services/
# 审查指定目录
```

### 审查重点
```bash
/code-review --focus=security
# 重点关注安全问题

/code-review --focus=performance
# 重点关注性能问题

/code-review --focus=maintainability
# 重点关注可维护性
```

### 输出格式
```bash
/code-review --format=summary
# 输出摘要报告

/code-review --format=detailed
# 输出详细报告

/code-review --format=checklist
# 输出修复清单格式
```

这个代码审查命令能够：
1. **全面评估**代码的各个质量维度
2. **分类问题**并提供明确的修复指导
3. **优先级排序**帮助开发者合理安排修复工作
4. **持续改进**建立代码质量的持续提升机制
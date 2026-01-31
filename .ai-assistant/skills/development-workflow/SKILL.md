---
name: development-workflow
description: 标准化开发工作流程，适用于各种编程语言和技术栈
version: 1.0.0
platform: universal
---

# 通用开发工作流程

一套经过实践验证的开发工作流程，适用于各种编程语言、框架和团队规模。

## 核心理念

### 质量优先
- **代码质量** > 开发速度
- **长期可维护性** > 短期便利
- **团队协作** > 个人偏好
- **持续改进** > 一次性完美

### 渐进式开发
- **小步快跑**：频繁的小幅改进
- **持续集成**：每次提交都是可工作的
- **快速反馈**：尽早发现和修复问题
- **迭代优化**：基于反馈持续改进

## 完整工作流程

### 阶段 1：需求理解 (Understanding)
```
🎯 目标：深入理解要解决的问题

📋 任务清单
├── 阅读需求文档和用户故事
├── 分析现有代码和架构
├── 识别相关模块和依赖
├── 明确验收标准
├── 评估技术风险
└── 制定实施计划

⏱️ 时间分配：总开发时间的 20%
🎯 输出：需求理解文档、风险评估、开发计划
```

#### 具体步骤
```markdown
## 1.1 需求分析
- **功能需求**：用户期望的功能和行为
- **非功能需求**：性能、安全、可用性要求
- **业务规则**：约束条件和业务逻辑
- **用户场景**：典型使用场景和边界情况

## 1.2 技术调研
- **现有架构**：了解当前系统设计
- **相关模块**：识别需要修改的组件
- **依赖关系**：分析模块间的依赖
- **技术选型**：评估需要的技术和工具

## 1.3 风险识别
- **技术风险**：新技术、复杂算法、性能要求
- **集成风险**：与现有系统的集成复杂度
- **时间风险**：开发时间估算的不确定性
- **质量风险**：测试覆盖、代码质量要求
```

### 阶段 2：方案设计 (Design)
```
🎯 目标：制定可行的技术实现方案

📋 任务清单
├── 设计系统架构
├── 定义接口和数据结构
├── 选择技术栈和工具
├── 设计数据库模式
├── 规划模块划分
└── 评估性能影响

⏱️ 时间分配：总开发时间的 25%
🎯 输出：技术设计文档、接口定义、数据模型
```

#### 设计原则
```markdown
## 2.1 架构设计
- **模块化**：高内聚、低耦合的模块设计
- **可扩展**：支持未来功能扩展
- **可测试**：便于单元测试和集成测试
- **可维护**：清晰的代码结构和文档

## 2.2 接口设计
- **RESTful API**：遵循 REST 设计原则
- **数据格式**：统一的请求/响应格式
- **错误处理**：标准化的错误码和消息
- **版本管理**：API 版本控制策略

## 2.3 数据设计
- **数据模型**：实体关系和属性定义
- **存储方案**：数据库选择和表结构设计
- **索引策略**：查询性能优化
- **数据迁移**：版本升级和数据迁移方案
```

### 阶段 3：增量实现 (Implementation)
```
🎯 目标：分步骤实现功能，保持代码随时可运行

📋 任务清单
├── 搭建基础框架
├── 实现核心逻辑
├── 添加边界处理
├── 集成外部依赖
├── 优化性能
└── 完善错误处理

⏱️ 时间分配：总开发时间的 40%
🎯 输出：可工作的代码、单元测试、集成测试
```

#### 实现策略
```markdown
## 3.1 MVP 优先
- **核心功能**：先实现最小可行产品
- **基础框架**：搭建基本的代码结构
- **主要流程**：实现核心业务逻辑
- **基本测试**：确保核心功能正常工作

## 3.2 迭代增强
- **功能完善**：逐步添加完整功能
- **边界处理**：处理异常和边界情况
- **性能优化**：优化关键路径性能
- **用户体验**：改进交互和反馈

## 3.3 质量保证
- **代码审查**：每次提交都进行代码审查
- **自动测试**：运行完整的测试套件
- **集成测试**：验证模块间的协作
- **性能测试**：确保性能指标达标
```

### 阶段 4：质量验证 (Verification)
```
🎯 目标：确保代码质量和功能正确性

📋 任务清单
├── 运行静态代码分析
├── 执行单元测试
├── 进行集成测试
├── 性能基准测试
├── 安全漏洞扫描
└── 代码覆盖率检查

⏱️ 时间分配：总开发时间的 15%
🎯 输出：测试报告、质量报告、性能报告
```

#### 验证清单
```markdown
## 4.1 功能验证
- [ ] 所有功能按需求正常工作
- [ ] 边界条件处理正确
- [ ] 错误场景处理完整
- [ ] 用户体验符合预期

## 4.2 质量验证
- [ ] 代码符合编码规范
- [ ] 单元测试覆盖率 ≥ 80%
- [ ] 集成测试通过
- [ ] 静态代码分析无严重问题

## 4.3 性能验证
- [ ] 响应时间满足要求
- [ ] 并发处理能力达标
- [ ] 内存使用合理
- [ ] 数据库查询优化

## 4.4 安全验证
- [ ] 输入验证完整
- [ ] 权限控制正确
- [ ] 敏感数据保护
- [ ] 安全漏洞扫描通过
```

## 代码修改原则

### 最小改动原则
```markdown
✅ 遵循原则
- 只修改必要的代码
- 保持现有功能不受影响
- 优先使用现有的模式和工具
- 避免不相关的重构

❌ 避免行为
- 大范围的代码重构
- 修改不相关的代码
- 改变现有的 API 接口
- 引入不必要的依赖
```

### 保持一致性原则
```markdown
✅ 遵循原则
- 使用项目现有的代码风格
- 遵循团队约定的命名规范
- 保持目录结构的一致性
- 使用统一的错误处理模式

❌ 避免行为
- 引入新的代码风格
- 使用不同的命名约定
- 破坏现有的架构模式
- 忽略项目规范
```

### 向后兼容原则
```markdown
✅ 遵循原则
- API 变更考虑兼容性
- 数据库变更提供迁移脚本
- 配置变更提供默认值
- 功能变更提供降级方案

❌ 避免行为
- 破坏性的 API 变更
- 不兼容的数据格式变更
- 强制性的配置要求
- 没有回滚方案的变更
```

## 技术栈适配

### 前端开发流程
```javascript
// 1. 组件设计
interface UserProfileProps {
  userId: string
  onUpdate?: (user: User) => void
}

// 2. 逻辑抽离 (React Hooks / Vue Composables)
function useUserProfile(userId: string) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(false)
  
  const updateUser = useCallback(async (updates: Partial<User>) => {
    setLoading(true)
    try {
      const updatedUser = await userService.update(userId, updates)
      setUser(updatedUser)
    } finally {
      setLoading(false)
    }
  }, [userId])
  
  return { user, loading, updateUser }
}

// 3. 组件实现
function UserProfile({ userId, onUpdate }: UserProfileProps) {
  const { user, loading, updateUser } = useUserProfile(userId)
  
  if (loading) return <LoadingSpinner />
  if (!user) return <UserNotFound />
  
  return (
    <div className="user-profile">
      {/* UI 实现 */}
    </div>
  )
}
```

### 后端开发流程
```typescript
// 1. 接口定义
interface UserService {
  createUser(userData: CreateUserData): Promise<User>
  getUserById(id: string): Promise<User | null>
  updateUser(id: string, updates: Partial<User>): Promise<User>
  deleteUser(id: string): Promise<void>
}

// 2. 实现类
class UserServiceImpl implements UserService {
  constructor(
    private userRepository: UserRepository,
    private emailService: EmailService
  ) {}
  
  async createUser(userData: CreateUserData): Promise<User> {
    // 1. 验证输入
    const validation = validateUserData(userData)
    if (!validation.isValid) {
      throw new ValidationError(validation.errors)
    }
    
    // 2. 业务逻辑
    const user = await this.userRepository.save({
      ...userData,
      id: generateId(),
      createdAt: new Date()
    })
    
    // 3. 副作用
    await this.emailService.sendWelcomeEmail(user)
    
    return user
  }
}

// 3. 控制器
@Controller('/api/users')
class UserController {
  constructor(private userService: UserService) {}
  
  @Post('/')
  async createUser(@Body() userData: CreateUserData): Promise<ApiResponse<User>> {
    try {
      const user = await this.userService.createUser(userData)
      return { success: true, data: user }
    } catch (error) {
      if (error instanceof ValidationError) {
        return { success: false, error: error.message, code: 'VALIDATION_ERROR' }
      }
      throw error
    }
  }
}
```

### 数据库开发流程
```sql
-- 1. 数据模型设计
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  name VARCHAR(100) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. 索引优化
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);
CREATE INDEX CONCURRENTLY idx_users_created_at ON users(created_at);

-- 3. 查询优化
-- ❌ 避免 N+1 查询
SELECT * FROM orders WHERE user_id IN (
  SELECT id FROM users WHERE active = true
);

-- ✅ 使用 JOIN 优化
SELECT o.*, u.name as user_name 
FROM orders o
JOIN users u ON o.user_id = u.id 
WHERE u.active = true;
```

## 测试策略

### 测试金字塔
```
        /\
       /  \
      / E2E \     ← 少量端到端测试
     /______\
    /        \
   /Integration\ ← 适量集成测试
  /__________\
 /            \
/  Unit Tests  \   ← 大量单元测试
/______________\
```

### 单元测试
```typescript
// 测试业务逻辑
describe('UserService', () => {
  let userService: UserService
  let mockRepository: jest.Mocked<UserRepository>
  let mockEmailService: jest.Mocked<EmailService>
  
  beforeEach(() => {
    mockRepository = createMockRepository()
    mockEmailService = createMockEmailService()
    userService = new UserService(mockRepository, mockEmailService)
  })
  
  describe('createUser', () => {
    it('should create user with valid data', async () => {
      // Arrange
      const userData = { name: 'John', email: 'john@example.com' }
      const expectedUser = { id: '123', ...userData, createdAt: new Date() }
      mockRepository.save.mockResolvedValue(expectedUser)
      
      // Act
      const result = await userService.createUser(userData)
      
      // Assert
      expect(result).toEqual(expectedUser)
      expect(mockRepository.save).toHaveBeenCalledWith(
        expect.objectContaining(userData)
      )
      expect(mockEmailService.sendWelcomeEmail).toHaveBeenCalledWith(expectedUser)
    })
    
    it('should throw ValidationError for invalid email', async () => {
      // Arrange
      const userData = { name: 'John', email: 'invalid-email' }
      
      // Act & Assert
      await expect(userService.createUser(userData))
        .rejects.toThrow(ValidationError)
    })
  })
})
```

### 集成测试
```typescript
// 测试模块协作
describe('User API Integration', () => {
  let app: Application
  let database: Database
  
  beforeAll(async () => {
    app = await createTestApp()
    database = await setupTestDatabase()
  })
  
  afterAll(async () => {
    await cleanupTestDatabase(database)
    await app.close()
  })
  
  it('should create user end-to-end', async () => {
    // Act
    const response = await request(app)
      .post('/api/users')
      .send({ name: 'John', email: 'john@example.com' })
      .expect(201)
    
    // Assert
    expect(response.body.success).toBe(true)
    expect(response.body.data).toMatchObject({
      name: 'John',
      email: 'john@example.com'
    })
    
    // Verify database
    const user = await database.users.findById(response.body.data.id)
    expect(user).toBeTruthy()
  })
})
```

## 性能优化

### 前端性能
```typescript
// 1. 代码分割
const LazyComponent = React.lazy(() => import('./HeavyComponent'))

function App() {
  return (
    <Suspense fallback={<Loading />}>
      <LazyComponent />
    </Suspense>
  )
}

// 2. 缓存优化
const memoizedComponent = React.memo(ExpensiveComponent)

const memoizedValue = useMemo(() => {
  return expensiveCalculation(data)
}, [data])

// 3. 虚拟滚动
function VirtualList({ items }: { items: Item[] }) {
  const [visibleRange, setVisibleRange] = useState({ start: 0, end: 50 })
  
  return (
    <div className="virtual-list">
      {items.slice(visibleRange.start, visibleRange.end).map(item => (
        <ItemComponent key={item.id} item={item} />
      ))}
    </div>
  )
}
```

### 后端性能
```typescript
// 1. 数据库查询优化
class UserRepository {
  // 批量查询避免 N+1
  async findUsersWithProfiles(userIds: string[]): Promise<UserWithProfile[]> {
    const users = await this.db.users.findByIds(userIds)
    const profiles = await this.db.profiles.findByUserIds(userIds)
    
    const profileMap = new Map(profiles.map(p => [p.userId, p]))
    return users.map(user => ({
      ...user,
      profile: profileMap.get(user.id)
    }))
  }
  
  // 分页查询
  async findUsers(page: number, limit: number): Promise<PaginatedResult<User>> {
    const offset = (page - 1) * limit
    const [users, total] = await Promise.all([
      this.db.users.findMany({ offset, limit }),
      this.db.users.count()
    ])
    
    return {
      data: users,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    }
  }
}

// 2. 缓存策略
class CachedUserService {
  constructor(
    private userService: UserService,
    private cache: CacheService
  ) {}
  
  async getUserById(id: string): Promise<User | null> {
    const cacheKey = `user:${id}`
    
    // 尝试从缓存获取
    const cached = await this.cache.get<User>(cacheKey)
    if (cached) return cached
    
    // 从数据库获取
    const user = await this.userService.getUserById(id)
    if (user) {
      // 缓存 5 分钟
      await this.cache.set(cacheKey, user, 300)
    }
    
    return user
  }
}
```

## 错误处理

### 分层错误处理
```typescript
// 1. 业务错误
class BusinessError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 400
  ) {
    super(message)
    this.name = 'BusinessError'
  }
}

class ValidationError extends BusinessError {
  constructor(message: string, public field?: string) {
    super(message, 'VALIDATION_ERROR', 400)
  }
}

class NotFoundError extends BusinessError {
  constructor(resource: string, id: string) {
    super(`${resource} with id ${id} not found`, 'NOT_FOUND', 404)
  }
}

// 2. 全局错误处理
function globalErrorHandler(error: Error, req: Request, res: Response, next: NextFunction) {
  if (error instanceof BusinessError) {
    return res.status(error.statusCode).json({
      success: false,
      error: error.message,
      code: error.code
    })
  }
  
  // 系统错误
  console.error('Unexpected error:', error)
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    code: 'INTERNAL_ERROR'
  })
}

// 3. 异步错误处理
function asyncHandler(fn: Function) {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next)
  }
}
```

## 部署和监控

### CI/CD 流程
```yaml
# .github/workflows/ci.yml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'
      
      - run: npm ci
      - run: npm run lint
      - run: npm run type-check
      - run: npm run test:coverage
      - run: npm run build
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm audit
      - run: npm run security-scan
      
  deploy:
    needs: [test, security]
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to production
        run: echo "Deploying to production..."
```

### 监控和告警
```typescript
// 应用监控
class MonitoringService {
  // 性能监控
  trackPerformance(operation: string, duration: number) {
    metrics.histogram('operation_duration', duration, { operation })
    
    if (duration > 1000) {
      logger.warn(`Slow operation detected: ${operation} took ${duration}ms`)
    }
  }
  
  // 错误监控
  trackError(error: Error, context: any) {
    metrics.counter('errors_total', { 
      type: error.constructor.name,
      operation: context.operation 
    })
    
    logger.error('Application error', { error, context })
  }
  
  // 业务指标监控
  trackBusinessMetric(metric: string, value: number, tags: Record<string, string>) {
    metrics.gauge(metric, value, tags)
  }
}

// 健康检查
app.get('/health', async (req, res) => {
  const checks = await Promise.allSettled([
    checkDatabase(),
    checkRedis(),
    checkExternalAPI()
  ])
  
  const health = {
    status: checks.every(c => c.status === 'fulfilled') ? 'healthy' : 'unhealthy',
    timestamp: new Date().toISOString(),
    checks: checks.map((check, index) => ({
      name: ['database', 'redis', 'external-api'][index],
      status: check.status === 'fulfilled' ? 'up' : 'down',
      error: check.status === 'rejected' ? check.reason.message : undefined
    }))
  }
  
  res.status(health.status === 'healthy' ? 200 : 503).json(health)
})
```

这套通用开发工作流程经过实践验证，能够显著提升开发效率和代码质量，适用于各种技术栈和团队规模。
# 架构设计原则

## 核心设计原则

### SOLID 原则详解

#### 单一职责原则 (Single Responsibility Principle)
```typescript
// ❌ 违反 SRP - 一个类承担多个职责
class User {
  constructor(public name: string, public email: string) {}
  
  // 用户数据验证
  validate(): boolean {
    return this.email.includes('@')
  }
  
  // 数据库操作
  save(): void {
    database.users.insert(this)
  }
  
  // 邮件发送
  sendWelcomeEmail(): void {
    emailService.send(this.email, 'Welcome!')
  }
}

// ✅ 遵循 SRP - 职责分离
class User {
  constructor(public name: string, public email: string) {}
}

class UserValidator {
  validate(user: User): boolean {
    return user.email.includes('@')
  }
}

class UserRepository {
  save(user: User): void {
    database.users.insert(user)
  }
}

class UserNotificationService {
  sendWelcomeEmail(user: User): void {
    emailService.send(user.email, 'Welcome!')
  }
}
```

#### 开闭原则 (Open-Closed Principle)
```typescript
// ❌ 违反 OCP - 修改现有代码添加新功能
class PaymentProcessor {
  process(payment: Payment): void {
    if (payment.type === 'credit_card') {
      // 信用卡处理逻辑
    } else if (payment.type === 'paypal') {
      // PayPal 处理逻辑
    } else if (payment.type === 'alipay') { // 新增需要修改现有代码
      // 支付宝处理逻辑
    }
  }
}

// ✅ 遵循 OCP - 通过扩展添加新功能
interface PaymentMethod {
  process(amount: number): Promise<PaymentResult>
}

class CreditCardPayment implements PaymentMethod {
  async process(amount: number): Promise<PaymentResult> {
    // 信用卡处理逻辑
    return { success: true, transactionId: 'cc_123' }
  }
}

class PayPalPayment implements PaymentMethod {
  async process(amount: number): Promise<PaymentResult> {
    // PayPal 处理逻辑
    return { success: true, transactionId: 'pp_456' }
  }
}

class PaymentProcessor {
  constructor(private paymentMethod: PaymentMethod) {}
  
  async process(amount: number): Promise<PaymentResult> {
    return this.paymentMethod.process(amount)
  }
}

// 添加新支付方式无需修改现有代码
class AlipayPayment implements PaymentMethod {
  async process(amount: number): Promise<PaymentResult> {
    return { success: true, transactionId: 'ap_789' }
  }
}
```

#### 里氏替换原则 (Liskov Substitution Principle)
```typescript
// ❌ 违反 LSP - 子类改变了基类的行为契约
class Bird {
  fly(): void {
    console.log('Flying...')
  }
}

class Penguin extends Bird {
  fly(): void {
    throw new Error('Penguins cannot fly!') // 违反了基类契约
  }
}

// ✅ 遵循 LSP - 正确的抽象层次
abstract class Bird {
  abstract move(): void
}

class FlyingBird extends Bird {
  move(): void {
    this.fly()
  }
  
  private fly(): void {
    console.log('Flying...')
  }
}

class SwimmingBird extends Bird {
  move(): void {
    this.swim()
  }
  
  private swim(): void {
    console.log('Swimming...')
  }
}

class Eagle extends FlyingBird {} // 可以替换 FlyingBird
class Penguin extends SwimmingBird {} // 可以替换 SwimmingBird
```

#### 接口隔离原则 (Interface Segregation Principle)
```typescript
// ❌ 违反 ISP - 臃肿的接口
interface Worker {
  work(): void
  eat(): void
  sleep(): void
  code(): void
  design(): void
  test(): void
}

class Developer implements Worker {
  work(): void { this.code() }
  eat(): void { /* 实现 */ }
  sleep(): void { /* 实现 */ }
  code(): void { /* 实现 */ }
  design(): void { /* 实现 */ }
  test(): void { /* 不需要但必须实现 */ }
}

// ✅ 遵循 ISP - 细粒度接口
interface Workable {
  work(): void
}

interface Eatable {
  eat(): void
}

interface Sleepable {
  sleep(): void
}

interface Codeable {
  code(): void
}

interface Designable {
  design(): void
}

interface Testable {
  test(): void
}

class Developer implements Workable, Eatable, Sleepable, Codeable, Designable {
  work(): void { this.code() }
  eat(): void { /* 实现 */ }
  sleep(): void { /* 实现 */ }
  code(): void { /* 实现 */ }
  design(): void { /* 实现 */ }
}

class Tester implements Workable, Eatable, Sleepable, Testable {
  work(): void { this.test() }
  eat(): void { /* 实现 */ }
  sleep(): void { /* 实现 */ }
  test(): void { /* 实现 */ }
}
```

#### 依赖倒置原则 (Dependency Inversion Principle)
```typescript
// ❌ 违反 DIP - 高层模块依赖低层模块
class MySQLDatabase {
  save(data: any): void {
    // MySQL 特定的保存逻辑
  }
}

class UserService {
  private database = new MySQLDatabase() // 直接依赖具体实现
  
  createUser(userData: any): void {
    // 业务逻辑
    this.database.save(userData)
  }
}

// ✅ 遵循 DIP - 依赖抽象而非具体实现
interface Database {
  save(data: any): void
  find(id: string): any
  update(id: string, data: any): void
  delete(id: string): void
}

class MySQLDatabase implements Database {
  save(data: any): void { /* MySQL 实现 */ }
  find(id: string): any { /* MySQL 实现 */ }
  update(id: string, data: any): void { /* MySQL 实现 */ }
  delete(id: string): void { /* MySQL 实现 */ }
}

class PostgreSQLDatabase implements Database {
  save(data: any): void { /* PostgreSQL 实现 */ }
  find(id: string): any { /* PostgreSQL 实现 */ }
  update(id: string, data: any): void { /* PostgreSQL 实现 */ }
  delete(id: string): void { /* PostgreSQL 实现 */ }
}

class UserService {
  constructor(private database: Database) {} // 依赖抽象
  
  createUser(userData: any): void {
    // 业务逻辑
    this.database.save(userData)
  }
}

// 依赖注入
const userService = new UserService(new MySQLDatabase())
// 或者
const userService2 = new UserService(new PostgreSQLDatabase())
```

## 架构模式

### 分层架构 (Layered Architecture)
```
┌─────────────────────────────────────┐
│           表现层 (Presentation)      │  ← 用户界面、API 控制器
├─────────────────────────────────────┤
│           业务层 (Business)          │  ← 业务逻辑、领域服务
├─────────────────────────────────────┤
│           持久层 (Persistence)       │  ← 数据访问、仓储模式
├─────────────────────────────────────┤
│           数据层 (Database)          │  ← 数据库、文件系统
└─────────────────────────────────────┘
```

#### 实现示例
```typescript
// 数据层
interface UserRepository {
  findById(id: string): Promise<User | null>
  save(user: User): Promise<User>
  delete(id: string): Promise<void>
}

// 持久层实现
class DatabaseUserRepository implements UserRepository {
  async findById(id: string): Promise<User | null> {
    const result = await database.query('SELECT * FROM users WHERE id = ?', [id])
    return result ? this.mapToUser(result) : null
  }
  
  async save(user: User): Promise<User> {
    const result = await database.query(
      'INSERT INTO users (name, email) VALUES (?, ?)',
      [user.name, user.email]
    )
    return { ...user, id: result.insertId }
  }
  
  async delete(id: string): Promise<void> {
    await database.query('DELETE FROM users WHERE id = ?', [id])
  }
}

// 业务层
class UserService {
  constructor(private userRepository: UserRepository) {}
  
  async createUser(userData: CreateUserData): Promise<User> {
    // 业务规则验证
    if (!this.isValidEmail(userData.email)) {
      throw new BusinessError('Invalid email format')
    }
    
    // 业务逻辑
    const user = new User(userData.name, userData.email)
    return this.userRepository.save(user)
  }
  
  private isValidEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  }
}

// 表现层
class UserController {
  constructor(private userService: UserService) {}
  
  async createUser(req: Request, res: Response): Promise<void> {
    try {
      const user = await this.userService.createUser(req.body)
      res.status(201).json({ success: true, data: user })
    } catch (error) {
      if (error instanceof BusinessError) {
        res.status(400).json({ success: false, error: error.message })
      } else {
        res.status(500).json({ success: false, error: 'Internal server error' })
      }
    }
  }
}
```

### 六边形架构 (Hexagonal Architecture)
```
        ┌─────────────────┐
        │   外部适配器     │
        │  (Web, CLI)     │
        └─────────┬───────┘
                  │
        ┌─────────▼───────┐
        │      端口       │
        │   (接口定义)     │
        └─────────┬───────┘
                  │
        ┌─────────▼───────┐
        │   应用核心       │
        │   (业务逻辑)     │
        └─────────┬───────┘
                  │
        ┌─────────▼───────┐
        │      端口       │
        │   (接口定义)     │
        └─────────┬───────┘
                  │
        ┌─────────▼───────┐
        │   外部适配器     │
        │ (数据库, 消息队列) │
        └─────────────────┘
```

#### 实现示例
```typescript
// 核心业务逻辑
class OrderService {
  constructor(
    private orderRepository: OrderRepository,
    private paymentService: PaymentService,
    private notificationService: NotificationService
  ) {}
  
  async processOrder(orderData: OrderData): Promise<Order> {
    // 纯业务逻辑，不依赖外部实现细节
    const order = new Order(orderData)
    
    // 验证订单
    if (!order.isValid()) {
      throw new InvalidOrderError('Order validation failed')
    }
    
    // 处理支付
    const paymentResult = await this.paymentService.processPayment(order.total)
    if (!paymentResult.success) {
      throw new PaymentFailedError('Payment processing failed')
    }
    
    // 保存订单
    const savedOrder = await this.orderRepository.save(order)
    
    // 发送通知
    await this.notificationService.sendOrderConfirmation(savedOrder)
    
    return savedOrder
  }
}

// 端口定义 (接口)
interface OrderRepository {
  save(order: Order): Promise<Order>
  findById(id: string): Promise<Order | null>
}

interface PaymentService {
  processPayment(amount: number): Promise<PaymentResult>
}

interface NotificationService {
  sendOrderConfirmation(order: Order): Promise<void>
}

// 适配器实现
class DatabaseOrderRepository implements OrderRepository {
  async save(order: Order): Promise<Order> {
    // 数据库特定实现
    return database.orders.insert(order)
  }
  
  async findById(id: string): Promise<Order | null> {
    return database.orders.findById(id)
  }
}

class StripePaymentService implements PaymentService {
  async processPayment(amount: number): Promise<PaymentResult> {
    // Stripe 特定实现
    return stripe.charges.create({ amount })
  }
}

class EmailNotificationService implements NotificationService {
  async sendOrderConfirmation(order: Order): Promise<void> {
    // 邮件服务特定实现
    return emailService.send(order.customerEmail, 'Order Confirmation')
  }
}
```

### 微服务架构 (Microservices Architecture)
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   用户服务   │    │   订单服务   │    │   支付服务   │
│             │    │             │    │             │
│ ┌─────────┐ │    │ ┌─────────┐ │    │ ┌─────────┐ │
│ │   API   │ │    │ │   API   │ │    │ │   API   │ │
│ └─────────┘ │    │ └─────────┘ │    │ └─────────┘ │
│ ┌─────────┐ │    │ ┌─────────┐ │    │ ┌─────────┐ │
│ │ 业务逻辑 │ │    │ │ 业务逻辑 │ │    │ │ 业务逻辑 │ │
│ └─────────┘ │    │ └─────────┘ │    │ └─────────┘ │
│ ┌─────────┐ │    │ ┌─────────┐ │    │ ┌─────────┐ │
│ │  数据库  │ │    │ │  数据库  │ │    │ │  数据库  │ │
│ └─────────┘ │    │ └─────────┘ │    │ └─────────┘ │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                  ┌─────────▼───────┐
                  │    API 网关     │
                  │   服务发现      │
                  │   负载均衡      │
                  └─────────────────┘
```

#### 设计原则
```typescript
// 服务边界设计
class UserMicroservice {
  // 用户相关的所有功能
  async createUser(userData: UserData): Promise<User> { /* */ }
  async updateUser(id: string, updates: Partial<User>): Promise<User> { /* */ }
  async getUserById(id: string): Promise<User | null> { /* */ }
  async authenticateUser(credentials: Credentials): Promise<AuthResult> { /* */ }
}

class OrderMicroservice {
  // 订单相关的所有功能
  async createOrder(orderData: OrderData): Promise<Order> { /* */ }
  async updateOrderStatus(id: string, status: OrderStatus): Promise<Order> { /* */ }
  async getOrderById(id: string): Promise<Order | null> { /* */ }
  
  // 通过 API 调用其他服务
  private async getUserById(userId: string): Promise<User> {
    return this.userServiceClient.getUser(userId)
  }
  
  private async processPayment(paymentData: PaymentData): Promise<PaymentResult> {
    return this.paymentServiceClient.processPayment(paymentData)
  }
}

// 服务间通信
interface ServiceClient {
  get<T>(path: string): Promise<T>
  post<T>(path: string, data: any): Promise<T>
}

class UserServiceClient {
  constructor(private client: ServiceClient) {}
  
  async getUser(id: string): Promise<User> {
    return this.client.get<User>(`/users/${id}`)
  }
  
  async createUser(userData: UserData): Promise<User> {
    return this.client.post<User>('/users', userData)
  }
}
```

## 数据架构模式

### 仓储模式 (Repository Pattern)
```typescript
// 领域实体
class User {
  constructor(
    public readonly id: string,
    public name: string,
    public email: string,
    public createdAt: Date = new Date()
  ) {}
  
  updateEmail(newEmail: string): void {
    if (!this.isValidEmail(newEmail)) {
      throw new Error('Invalid email format')
    }
    this.email = newEmail
  }
  
  private isValidEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  }
}

// 仓储接口
interface UserRepository {
  findById(id: string): Promise<User | null>
  findByEmail(email: string): Promise<User | null>
  findAll(page: number, limit: number): Promise<User[]>
  save(user: User): Promise<User>
  delete(id: string): Promise<void>
}

// 仓储实现
class DatabaseUserRepository implements UserRepository {
  constructor(private database: Database) {}
  
  async findById(id: string): Promise<User | null> {
    const row = await this.database.query(
      'SELECT * FROM users WHERE id = ?', 
      [id]
    )
    return row ? this.mapRowToUser(row) : null
  }
  
  async findByEmail(email: string): Promise<User | null> {
    const row = await this.database.query(
      'SELECT * FROM users WHERE email = ?', 
      [email]
    )
    return row ? this.mapRowToUser(row) : null
  }
  
  async save(user: User): Promise<User> {
    const exists = await this.findById(user.id)
    
    if (exists) {
      await this.database.query(
        'UPDATE users SET name = ?, email = ? WHERE id = ?',
        [user.name, user.email, user.id]
      )
    } else {
      await this.database.query(
        'INSERT INTO users (id, name, email, created_at) VALUES (?, ?, ?, ?)',
        [user.id, user.name, user.email, user.createdAt]
      )
    }
    
    return user
  }
  
  private mapRowToUser(row: any): User {
    return new User(row.id, row.name, row.email, row.created_at)
  }
}

// 内存仓储实现 (用于测试)
class InMemoryUserRepository implements UserRepository {
  private users = new Map<string, User>()
  
  async findById(id: string): Promise<User | null> {
    return this.users.get(id) || null
  }
  
  async findByEmail(email: string): Promise<User | null> {
    for (const user of this.users.values()) {
      if (user.email === email) return user
    }
    return null
  }
  
  async save(user: User): Promise<User> {
    this.users.set(user.id, user)
    return user
  }
  
  async delete(id: string): Promise<void> {
    this.users.delete(id)
  }
}
```

### 工作单元模式 (Unit of Work Pattern)
```typescript
interface UnitOfWork {
  registerNew(entity: any): void
  registerDirty(entity: any): void
  registerDeleted(entity: any): void
  commit(): Promise<void>
  rollback(): Promise<void>
}

class DatabaseUnitOfWork implements UnitOfWork {
  private newEntities: any[] = []
  private dirtyEntities: any[] = []
  private deletedEntities: any[] = []
  private transaction: Transaction | null = null
  
  constructor(private database: Database) {}
  
  registerNew(entity: any): void {
    this.newEntities.push(entity)
  }
  
  registerDirty(entity: any): void {
    this.dirtyEntities.push(entity)
  }
  
  registerDeleted(entity: any): void {
    this.deletedEntities.push(entity)
  }
  
  async commit(): Promise<void> {
    this.transaction = await this.database.beginTransaction()
    
    try {
      // 插入新实体
      for (const entity of this.newEntities) {
        await this.insertEntity(entity)
      }
      
      // 更新修改的实体
      for (const entity of this.dirtyEntities) {
        await this.updateEntity(entity)
      }
      
      // 删除实体
      for (const entity of this.deletedEntities) {
        await this.deleteEntity(entity)
      }
      
      await this.transaction.commit()
      this.clear()
    } catch (error) {
      await this.transaction.rollback()
      throw error
    }
  }
  
  async rollback(): Promise<void> {
    if (this.transaction) {
      await this.transaction.rollback()
    }
    this.clear()
  }
  
  private clear(): void {
    this.newEntities = []
    this.dirtyEntities = []
    this.deletedEntities = []
    this.transaction = null
  }
}
```

## 缓存架构模式

### 多级缓存架构
```typescript
interface CacheService {
  get<T>(key: string): Promise<T | null>
  set<T>(key: string, value: T, ttl?: number): Promise<void>
  delete(key: string): Promise<void>
  clear(): Promise<void>
}

class MultiLevelCacheService implements CacheService {
  constructor(
    private l1Cache: MemoryCache,    // L1: 内存缓存
    private l2Cache: RedisCache,     // L2: Redis 缓存
    private l3Cache: DatabaseCache   // L3: 数据库缓存
  ) {}
  
  async get<T>(key: string): Promise<T | null> {
    // L1 缓存查找
    let value = await this.l1Cache.get<T>(key)
    if (value !== null) {
      return value
    }
    
    // L2 缓存查找
    value = await this.l2Cache.get<T>(key)
    if (value !== null) {
      // 回填 L1 缓存
      await this.l1Cache.set(key, value, 300) // 5分钟
      return value
    }
    
    // L3 缓存查找
    value = await this.l3Cache.get<T>(key)
    if (value !== null) {
      // 回填 L2 和 L1 缓存
      await this.l2Cache.set(key, value, 1800) // 30分钟
      await this.l1Cache.set(key, value, 300)  // 5分钟
      return value
    }
    
    return null
  }
  
  async set<T>(key: string, value: T, ttl?: number): Promise<void> {
    // 写入所有缓存层
    await Promise.all([
      this.l1Cache.set(key, value, Math.min(ttl || 300, 300)),
      this.l2Cache.set(key, value, Math.min(ttl || 1800, 1800)),
      this.l3Cache.set(key, value, ttl)
    ])
  }
}

// 缓存策略
class CacheAsidePattern<T> {
  constructor(
    private cache: CacheService,
    private dataSource: DataSource<T>
  ) {}
  
  async get(key: string): Promise<T | null> {
    // 1. 尝试从缓存获取
    let data = await this.cache.get<T>(key)
    
    if (data === null) {
      // 2. 缓存未命中，从数据源获取
      data = await this.dataSource.get(key)
      
      if (data !== null) {
        // 3. 写入缓存
        await this.cache.set(key, data)
      }
    }
    
    return data
  }
  
  async set(key: string, data: T): Promise<void> {
    // 1. 更新数据源
    await this.dataSource.set(key, data)
    
    // 2. 更新缓存
    await this.cache.set(key, data)
  }
  
  async delete(key: string): Promise<void> {
    // 1. 删除数据源
    await this.dataSource.delete(key)
    
    // 2. 删除缓存
    await this.cache.delete(key)
  }
}
```

## 安全架构原则

### 深度防御 (Defense in Depth)
```typescript
// 多层安全验证
class SecurityMiddleware {
  // 第一层：网络层安全
  async rateLimitCheck(req: Request): Promise<void> {
    const clientIp = req.ip
    const requestCount = await this.rateLimiter.getCount(clientIp)
    
    if (requestCount > this.config.maxRequestsPerMinute) {
      throw new TooManyRequestsError('Rate limit exceeded')
    }
  }
  
  // 第二层：认证
  async authenticateUser(req: Request): Promise<User> {
    const token = this.extractToken(req)
    
    if (!token) {
      throw new UnauthorizedError('Missing authentication token')
    }
    
    const user = await this.tokenService.validateToken(token)
    
    if (!user) {
      throw new UnauthorizedError('Invalid token')
    }
    
    return user
  }
  
  // 第三层：授权
  async authorizeAction(user: User, resource: string, action: string): Promise<void> {
    const hasPermission = await this.permissionService.checkPermission(
      user.id, 
      resource, 
      action
    )
    
    if (!hasPermission) {
      throw new ForbiddenError('Insufficient permissions')
    }
  }
  
  // 第四层：输入验证
  async validateInput(data: any, schema: ValidationSchema): Promise<void> {
    const result = await this.validator.validate(data, schema)
    
    if (!result.isValid) {
      throw new ValidationError('Invalid input', result.errors)
    }
  }
  
  // 第五层：输出编码
  sanitizeOutput(data: any): any {
    return this.sanitizer.sanitize(data, {
      allowedTags: [],
      allowedAttributes: {}
    })
  }
}

// 安全的数据访问层
class SecureDataAccess {
  async executeQuery(query: string, params: any[], user: User): Promise<any> {
    // 1. SQL 注入防护
    const sanitizedQuery = this.sqlSanitizer.sanitize(query)
    
    // 2. 参数化查询
    const preparedStatement = await this.database.prepare(sanitizedQuery)
    
    // 3. 行级安全检查
    const securityContext = this.buildSecurityContext(user)
    
    // 4. 执行查询
    const result = await preparedStatement.execute(params, securityContext)
    
    // 5. 结果过滤
    return this.filterSensitiveData(result, user)
  }
  
  private buildSecurityContext(user: User): SecurityContext {
    return {
      userId: user.id,
      roles: user.roles,
      permissions: user.permissions,
      organizationId: user.organizationId
    }
  }
  
  private filterSensitiveData(data: any, user: User): any {
    // 根据用户权限过滤敏感字段
    const allowedFields = this.permissionService.getAllowedFields(user)
    return this.fieldFilter.filter(data, allowedFields)
  }
}
```

## 性能架构原则

### 异步处理架构
```typescript
// 事件驱动架构
class EventDrivenArchitecture {
  constructor(
    private eventBus: EventBus,
    private eventStore: EventStore
  ) {}
  
  async processCommand(command: Command): Promise<void> {
    // 1. 命令验证
    await this.validateCommand(command)
    
    // 2. 生成事件
    const events = await this.generateEvents(command)
    
    // 3. 持久化事件
    await this.eventStore.saveEvents(events)
    
    // 4. 发布事件 (异步)
    for (const event of events) {
      await this.eventBus.publish(event)
    }
  }
  
  // 事件处理器
  @EventHandler('UserCreated')
  async handleUserCreated(event: UserCreatedEvent): Promise<void> {
    // 异步处理，不阻塞主流程
    await Promise.all([
      this.sendWelcomeEmail(event.user),
      this.createUserProfile(event.user),
      this.updateStatistics(event.user)
    ])
  }
  
  @EventHandler('OrderPlaced')
  async handleOrderPlaced(event: OrderPlacedEvent): Promise<void> {
    // 并行处理多个任务
    await Promise.all([
      this.updateInventory(event.order),
      this.processPayment(event.order),
      this.sendOrderConfirmation(event.order),
      this.updateAnalytics(event.order)
    ])
  }
}

// 消息队列架构
class MessageQueueArchitecture {
  constructor(
    private messageQueue: MessageQueue,
    private deadLetterQueue: MessageQueue
  ) {}
  
  async publishMessage(topic: string, message: any): Promise<void> {
    const messageWithMetadata = {
      id: generateId(),
      topic,
      payload: message,
      timestamp: new Date(),
      retryCount: 0,
      maxRetries: 3
    }
    
    await this.messageQueue.publish(topic, messageWithMetadata)
  }
  
  async processMessage(message: Message): Promise<void> {
    try {
      const handler = this.getHandler(message.topic)
      await handler.handle(message.payload)
      
      // 确认消息处理成功
      await this.messageQueue.ack(message.id)
    } catch (error) {
      await this.handleMessageError(message, error)
    }
  }
  
  private async handleMessageError(message: Message, error: Error): Promise<void> {
    message.retryCount++
    
    if (message.retryCount <= message.maxRetries) {
      // 重试处理
      const delay = Math.pow(2, message.retryCount) * 1000 // 指数退避
      await this.scheduleRetry(message, delay)
    } else {
      // 发送到死信队列
      await this.deadLetterQueue.publish('failed_messages', {
        originalMessage: message,
        error: error.message,
        failedAt: new Date()
      })
    }
  }
}
```

这些架构原则为构建高质量、可维护、可扩展的软件系统提供了坚实的基础。每个原则都经过实践验证，能够有效解决常见的架构问题。
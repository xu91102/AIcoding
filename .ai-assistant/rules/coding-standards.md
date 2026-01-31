# 编码规范

## 核心原则

### SOLID 原则
| 原则 | 说明 | 应用场景 |
|------|------|----------|
| **单一职责 (SRP)** | 每个类/函数只做一件事 | 类设计、函数拆分 |
| **开闭原则 (OCP)** | 对扩展开放，对修改关闭 | 插件系统、策略模式 |
| **里氏替换 (LSP)** | 子类可以替换父类 | 继承设计、多态 |
| **接口隔离 (ISP)** | 接口应该小而专一 | API 设计、依赖注入 |
| **依赖倒置 (DIP)** | 依赖抽象而非具体实现 | 架构设计、测试 |

### 设计原则
- **DRY (Don't Repeat Yourself)**：避免重复代码
- **KISS (Keep It Simple, Stupid)**：保持简单
- **YAGNI (You Aren't Gonna Need It)**：不要过度设计
- **低耦合高内聚**：模块间依赖最小化

## 命名规范

### 通用命名原则
```javascript
// ✅ 好的命名 - 清晰表达意图
const getUserById = (id) => { /* ... */ }
const isValidEmail = (email) => { /* ... */ }
const MAX_RETRY_COUNT = 3

// ❌ 不好的命名 - 意义不明
const getData = () => { /* ... */ }
const flag = true
const temp = 'something'
```

### 语言特定规范

#### JavaScript/TypeScript
```typescript
// 变量和函数：camelCase
const userName = 'john'
const calculateTotalPrice = () => { /* ... */ }

// 类：PascalCase
class UserService { /* ... */ }

// 常量：UPPER_SNAKE_CASE
const API_BASE_URL = 'https://api.example.com'

// 接口：PascalCase + I 前缀（可选）
interface IUserRepository { /* ... */ }
interface UserRepository { /* ... */ } // 也可接受

// 类型：PascalCase
type UserStatus = 'active' | 'inactive'
```

#### Python
```python
# 变量和函数：snake_case
user_name = 'john'
def calculate_total_price(): pass

# 类：PascalCase
class UserService: pass

# 常量：UPPER_SNAKE_CASE
API_BASE_URL = 'https://api.example.com'

# 私有成员：_ 前缀
def _internal_method(): pass
```

#### Java
```java
// 变量和方法：camelCase
String userName = "john";
public void calculateTotalPrice() { /* ... */ }

// 类：PascalCase
public class UserService { /* ... */ }

// 常量：UPPER_SNAKE_CASE
public static final String API_BASE_URL = "https://api.example.com";

// 包：lowercase
package com.example.userservice;
```

## 代码结构

### 文件组织
```
✅ 按功能模块组织
src/
├── user/
│   ├── UserService.ts
│   ├── UserRepository.ts
│   └── UserController.ts
├── order/
│   ├── OrderService.ts
│   └── OrderRepository.ts
└── shared/
    ├── utils/
    └── types/

❌ 按技术类型组织
src/
├── controllers/
├── services/
├── repositories/
└── models/
```

### 导入顺序
```typescript
// 1. 标准库导入
import fs from 'fs'
import path from 'path'

// 2. 第三方库导入
import express from 'express'
import lodash from 'lodash'

// 3. 内部模块导入
import { UserService } from '../services/UserService'
import { config } from '../config'

// 4. 相对路径导入
import './styles.css'
```

## 函数设计

### 函数大小和复杂度
```typescript
// ✅ 小而专一的函数
function validateEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

function validateUser(user: User): ValidationResult {
  const errors: string[] = []
  
  if (!user.name) errors.push('Name is required')
  if (!validateEmail(user.email)) errors.push('Invalid email')
  
  return {
    isValid: errors.length === 0,
    errors
  }
}

// ❌ 过长的函数
function processUser(userData: any): any {
  // 100+ 行代码处理用户的各个方面
  // 验证、转换、保存、发送邮件等
}
```

### 参数设计
```typescript
// ✅ 参数少于 5 个
function createUser(name: string, email: string, age: number): User {
  return { name, email, age }
}

// ✅ 超过 5 个参数时使用对象
interface CreateUserOptions {
  name: string
  email: string
  age: number
  address?: string
  phone?: string
  preferences?: UserPreferences
}

function createUser(options: CreateUserOptions): User {
  return { ...options }
}

// ❌ 参数过多
function createUser(
  name: string,
  email: string, 
  age: number,
  address: string,
  phone: string,
  city: string,
  country: string
): User {
  // 难以使用和维护
}
```

### 返回值设计
```typescript
// ✅ 明确的返回类型
function getUserById(id: string): Promise<User | null> {
  // 明确可能返回 null
}

function validateInput(input: string): ValidationResult {
  return {
    isValid: boolean,
    errors: string[],
    warnings: string[]
  }
}

// ✅ 使用 Result 模式处理错误
type Result<T, E = Error> = 
  | { success: true; data: T }
  | { success: false; error: E }

function parseJson<T>(json: string): Result<T> {
  try {
    const data = JSON.parse(json)
    return { success: true, data }
  } catch (error) {
    return { success: false, error: error as Error }
  }
}
```

## 错误处理

### 异常处理模式
```typescript
// ✅ 具体的错误类型
class ValidationError extends Error {
  constructor(
    message: string,
    public field: string,
    public value: any
  ) {
    super(message)
    this.name = 'ValidationError'
  }
}

// ✅ 早期返回
function processUser(user: User): ProcessResult {
  if (!user) {
    return { success: false, error: 'User is required' }
  }
  
  if (!user.email) {
    return { success: false, error: 'Email is required' }
  }
  
  // 主要逻辑
  return { success: true, data: processedUser }
}

// ✅ 异步错误处理
async function fetchUserData(id: string): Promise<User> {
  try {
    const response = await api.get(`/users/${id}`)
    return response.data
  } catch (error) {
    logger.error('Failed to fetch user', { id, error })
    throw new Error(`Failed to fetch user ${id}`)
  }
}
```

## 注释规范

### 文档注释
```typescript
/**
 * 计算两个日期之间的工作日数量
 * 
 * @param startDate - 开始日期
 * @param endDate - 结束日期
 * @param excludeHolidays - 是否排除节假日
 * @returns 工作日数量
 * 
 * @example
 * ```typescript
 * const workdays = calculateWorkdays(
 *   new Date('2024-01-01'),
 *   new Date('2024-01-31'),
 *   true
 * )
 * console.log(workdays) // 22
 * ```
 * 
 * @throws {ValidationError} 当日期无效时抛出
 */
function calculateWorkdays(
  startDate: Date,
  endDate: Date,
  excludeHolidays: boolean = false
): number {
  // 实现逻辑
}
```

### 行内注释
```typescript
// ✅ 解释"为什么"
function calculateDiscount(user: User, order: Order): number {
  // VIP 用户在周五享受额外 5% 折扣
  // 这是为了提高用户粘性的营销策略
  if (user.isVIP && isFriday()) {
    return order.amount * 0.05
  }
  
  return 0
}

// ❌ 重复代码内容
function calculateDiscount(user: User, order: Order): number {
  // 如果用户是 VIP 并且是周五
  if (user.isVIP && isFriday()) {
    // 返回订单金额乘以 0.05
    return order.amount * 0.05
  }
}
```

## 类型安全

### TypeScript 最佳实践
```typescript
// ✅ 严格的类型定义
interface User {
  readonly id: string
  name: string
  email: string
  createdAt: Date
  preferences?: UserPreferences
}

// ✅ 使用联合类型
type Status = 'pending' | 'approved' | 'rejected'

// ✅ 泛型约束
interface Repository<T extends { id: string }> {
  findById(id: string): Promise<T | null>
  save(entity: T): Promise<T>
}

// ✅ 类型守卫
function isUser(obj: any): obj is User {
  return obj && 
         typeof obj.id === 'string' &&
         typeof obj.name === 'string' &&
         typeof obj.email === 'string'
}

// ❌ 避免使用 any
function processData(data: any): any {
  return data.whatever.something
}
```

## 性能考虑

### 算法复杂度
```typescript
// ✅ O(1) 查找
const userMap = new Map<string, User>()
const user = userMap.get(userId) // O(1)

// ✅ 避免 O(n²) 嵌套循环
const userIds = new Set(users.map(u => u.id))
const filteredOrders = orders.filter(o => userIds.has(o.userId))

// ❌ O(n²) 性能问题
const filteredOrders = orders.filter(order => 
  users.some(user => user.id === order.userId)
)
```

### 内存管理
```typescript
// ✅ 及时清理资源
class DataProcessor {
  private cache = new Map()
  
  process(data: Data[]): Result[] {
    try {
      return data.map(item => this.processItem(item))
    } finally {
      this.cache.clear() // 清理缓存
    }
  }
}

// ✅ 使用 WeakMap 避免内存泄漏
const metadata = new WeakMap<object, Metadata>()
```

## 测试友好的代码

### 依赖注入
```typescript
// ✅ 可测试的设计
class UserService {
  constructor(
    private userRepository: UserRepository,
    private emailService: EmailService
  ) {}
  
  async createUser(userData: CreateUserData): Promise<User> {
    const user = await this.userRepository.save(userData)
    await this.emailService.sendWelcomeEmail(user)
    return user
  }
}

// ❌ 难以测试的设计
class UserService {
  async createUser(userData: CreateUserData): Promise<User> {
    const user = await database.users.save(userData) // 硬依赖
    await sendEmail(user.email, 'Welcome!') // 硬依赖
    return user
  }
}
```

### 纯函数优先
```typescript
// ✅ 纯函数 - 易于测试
function calculateTax(amount: number, rate: number): number {
  return amount * rate
}

// ✅ 副作用隔离
function processOrder(order: Order, services: Services): OrderResult {
  const validationResult = validateOrder(order) // 纯函数
  if (!validationResult.isValid) {
    return { success: false, errors: validationResult.errors }
  }
  
  // 副作用集中处理
  return services.orderProcessor.process(order)
}
```

这些编码规范将确保代码的质量、可维护性和团队协作效率。
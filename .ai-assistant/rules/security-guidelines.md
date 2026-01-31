# 安全开发规范

## 核心安全原则

### 零信任架构 (Zero Trust)
- **永不信任，始终验证**：对所有请求进行身份验证和授权
- **最小权限原则**：只授予完成任务所需的最小权限
- **持续监控**：实时监控和审计所有访问行为
- **动态访问控制**：基于上下文的动态权限调整

### 深度防御 (Defense in Depth)
```
┌─────────────────────────────────────────┐
│              网络安全层                  │  ← 防火墙、DDoS 防护
├─────────────────────────────────────────┤
│              应用安全层                  │  ← WAF、API 网关
├─────────────────────────────────────────┤
│              认证授权层                  │  ← OAuth、JWT、RBAC
├─────────────────────────────────────────┤
│              业务逻辑层                  │  ← 输入验证、业务规则
├─────────────────────────────────────────┤
│              数据访问层                  │  ← SQL 防注入、ORM
├─────────────────────────────────────────┤
│              数据存储层                  │  ← 加密、备份、审计
└─────────────────────────────────────────┘
```

## 输入验证和数据清理

### 输入验证原则
```typescript
// ✅ 严格的输入验证
class InputValidator {
  static validateEmail(email: string): boolean {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/
    return emailRegex.test(email) && email.length <= 254
  }
  
  static validatePassword(password: string): ValidationResult {
    const errors: string[] = []
    
    if (password.length < 12) {
      errors.push('密码长度至少 12 位')
    }
    
    if (!/[A-Z]/.test(password)) {
      errors.push('密码必须包含大写字母')
    }
    
    if (!/[a-z]/.test(password)) {
      errors.push('密码必须包含小写字母')
    }
    
    if (!/\d/.test(password)) {
      errors.push('密码必须包含数字')
    }
    
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push('密码必须包含特殊字符')
    }
    
    return {
      isValid: errors.length === 0,
      errors
    }
  }
  
  static sanitizeHtml(input: string): string {
    return input
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;')
  }
  
  static validateSqlInput(input: string): boolean {
    // 检查 SQL 注入模式
    const sqlInjectionPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)/i,
      /(--|\/\*|\*\/|;)/,
      /(\b(OR|AND)\b.*=.*)/i,
      /'.*'/
    ]
    
    return !sqlInjectionPatterns.some(pattern => pattern.test(input))
  }
}

// ❌ 危险的输入处理
function unsafeQuery(userInput: string): string {
  return `SELECT * FROM users WHERE name = '${userInput}'` // SQL 注入风险
}

// ✅ 安全的参数化查询
async function safeQuery(userInput: string): Promise<User[]> {
  // 1. 输入验证
  if (!InputValidator.validateSqlInput(userInput)) {
    throw new SecurityError('Invalid input detected')
  }
  
  // 2. 参数化查询
  const query = 'SELECT * FROM users WHERE name = ?'
  return database.query(query, [userInput])
}
```

### 文件上传安全
```typescript
class SecureFileUpload {
  private readonly allowedMimeTypes = [
    'image/jpeg',
    'image/png', 
    'image/gif',
    'application/pdf',
    'text/plain'
  ]
  
  private readonly maxFileSize = 10 * 1024 * 1024 // 10MB
  
  async validateFile(file: UploadedFile): Promise<ValidationResult> {
    const errors: string[] = []
    
    // 1. 文件大小检查
    if (file.size > this.maxFileSize) {
      errors.push(`文件大小超过限制 (${this.maxFileSize / 1024 / 1024}MB)`)
    }
    
    // 2. MIME 类型检查
    if (!this.allowedMimeTypes.includes(file.mimetype)) {
      errors.push('不支持的文件类型')
    }
    
    // 3. 文件扩展名检查
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt']
    const fileExtension = path.extname(file.originalname).toLowerCase()
    
    if (!allowedExtensions.includes(fileExtension)) {
      errors.push('不支持的文件扩展名')
    }
    
    // 4. 文件内容检查 (魔数验证)
    const isValidContent = await this.validateFileContent(file)
    if (!isValidContent) {
      errors.push('文件内容与扩展名不匹配')
    }
    
    return {
      isValid: errors.length === 0,
      errors
    }
  }
  
  private async validateFileContent(file: UploadedFile): Promise<boolean> {
    const buffer = await fs.readFile(file.path)
    const fileType = await import('file-type')
    const detectedType = await fileType.fileTypeFromBuffer(buffer)
    
    return detectedType?.mime === file.mimetype
  }
  
  async secureUpload(file: UploadedFile): Promise<string> {
    // 1. 验证文件
    const validation = await this.validateFile(file)
    if (!validation.isValid) {
      throw new ValidationError('File validation failed', validation.errors)
    }
    
    // 2. 生成安全的文件名
    const safeFileName = this.generateSafeFileName(file.originalname)
    
    // 3. 存储到安全目录
    const uploadPath = path.join(this.config.uploadDir, safeFileName)
    
    // 4. 移动文件
    await fs.move(file.path, uploadPath)
    
    // 5. 设置文件权限
    await fs.chmod(uploadPath, 0o644)
    
    return safeFileName
  }
  
  private generateSafeFileName(originalName: string): string {
    const extension = path.extname(originalName)
    const timestamp = Date.now()
    const randomString = crypto.randomBytes(16).toString('hex')
    
    return `${timestamp}_${randomString}${extension}`
  }
}
```

## 认证和授权

### JWT 安全实现
```typescript
class SecureJWTService {
  private readonly secretKey: string
  private readonly issuer: string
  private readonly audience: string
  
  constructor(config: JWTConfig) {
    this.secretKey = config.secretKey
    this.issuer = config.issuer
    this.audience = config.audience
  }
  
  generateToken(user: User): string {
    const payload = {
      sub: user.id,
      iss: this.issuer,
      aud: this.audience,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (15 * 60), // 15 分钟过期
      roles: user.roles,
      permissions: user.permissions
    }
    
    return jwt.sign(payload, this.secretKey, {
      algorithm: 'HS256',
      header: {
        typ: 'JWT',
        alg: 'HS256'
      }
    })
  }
  
  generateRefreshToken(user: User): string {
    const payload = {
      sub: user.id,
      type: 'refresh',
      iss: this.issuer,
      aud: this.audience,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60) // 7 天过期
    }
    
    return jwt.sign(payload, this.secretKey, { algorithm: 'HS256' })
  }
  
  async validateToken(token: string): Promise<TokenPayload | null> {
    try {
      const decoded = jwt.verify(token, this.secretKey, {
        algorithms: ['HS256'],
        issuer: this.issuer,
        audience: this.audience
      }) as TokenPayload
      
      // 检查令牌是否在黑名单中
      const isBlacklisted = await this.tokenBlacklist.isBlacklisted(token)
      if (isBlacklisted) {
        return null
      }
      
      return decoded
    } catch (error) {
      console.error('Token validation failed:', error)
      return null
    }
  }
  
  async revokeToken(token: string): Promise<void> {
    // 将令牌加入黑名单
    await this.tokenBlacklist.add(token)
  }
}

// 基于角色的访问控制 (RBAC)
class RBACService {
  async checkPermission(
    userId: string, 
    resource: string, 
    action: string
  ): Promise<boolean> {
    // 1. 获取用户角色
    const userRoles = await this.getUserRoles(userId)
    
    // 2. 获取角色权限
    const permissions = await this.getRolePermissions(userRoles)
    
    // 3. 检查权限
    return permissions.some(permission => 
      permission.resource === resource && 
      permission.actions.includes(action)
    )
  }
  
  async getUserRoles(userId: string): Promise<Role[]> {
    return this.database.query(
      'SELECT r.* FROM roles r JOIN user_roles ur ON r.id = ur.role_id WHERE ur.user_id = ?',
      [userId]
    )
  }
  
  async getRolePermissions(roles: Role[]): Promise<Permission[]> {
    const roleIds = roles.map(role => role.id)
    
    return this.database.query(
      'SELECT p.* FROM permissions p JOIN role_permissions rp ON p.id = rp.permission_id WHERE rp.role_id IN (?)',
      [roleIds]
    )
  }
}
```

### 多因素认证 (MFA)
```typescript
class MFAService {
  async generateTOTPSecret(userId: string): Promise<TOTPSecret> {
    const secret = speakeasy.generateSecret({
      name: `MyApp (${userId})`,
      issuer: 'MyApp',
      length: 32
    })
    
    // 存储密钥 (加密)
    await this.storeTOTPSecret(userId, secret.base32)
    
    return {
      secret: secret.base32,
      qrCode: secret.otpauth_url,
      backupCodes: this.generateBackupCodes()
    }
  }
  
  async verifyTOTP(userId: string, token: string): Promise<boolean> {
    const secret = await this.getTOTPSecret(userId)
    
    if (!secret) {
      return false
    }
    
    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 2 // 允许时间偏差
    })
    
    if (verified) {
      // 防止重放攻击 - 记录已使用的令牌
      await this.markTokenAsUsed(userId, token)
    }
    
    return verified
  }
  
  async sendSMSCode(phoneNumber: string): Promise<string> {
    const code = this.generateSMSCode()
    const hashedCode = await bcrypt.hash(code, 10)
    
    // 存储验证码 (5分钟过期)
    await this.redis.setex(`sms_code:${phoneNumber}`, 300, hashedCode)
    
    // 发送短信
    await this.smsService.send(phoneNumber, `验证码: ${code}`)
    
    return code
  }
  
  async verifySMSCode(phoneNumber: string, code: string): Promise<boolean> {
    const storedHash = await this.redis.get(`sms_code:${phoneNumber}`)
    
    if (!storedHash) {
      return false
    }
    
    const isValid = await bcrypt.compare(code, storedHash)
    
    if (isValid) {
      // 删除已使用的验证码
      await this.redis.del(`sms_code:${phoneNumber}`)
    }
    
    return isValid
  }
  
  private generateSMSCode(): string {
    return Math.floor(100000 + Math.random() * 900000).toString()
  }
  
  private generateBackupCodes(): string[] {
    const codes = []
    for (let i = 0; i < 10; i++) {
      codes.push(crypto.randomBytes(4).toString('hex').toUpperCase())
    }
    return codes
  }
}
```

## 数据保护

### 敏感数据加密
```typescript
class DataEncryption {
  private readonly algorithm = 'aes-256-gcm'
  private readonly keyDerivationIterations = 100000
  
  constructor(private masterKey: string) {}
  
  async encryptSensitiveData(data: string, context?: string): Promise<EncryptedData> {
    // 1. 生成随机盐和 IV
    const salt = crypto.randomBytes(32)
    const iv = crypto.randomBytes(16)
    
    // 2. 派生加密密钥
    const key = crypto.pbkdf2Sync(
      this.masterKey, 
      salt, 
      this.keyDerivationIterations, 
      32, 
      'sha256'
    )
    
    // 3. 创建加密器
    const cipher = crypto.createCipher(this.algorithm, key)
    cipher.setAAD(Buffer.from(context || '', 'utf8'))
    
    // 4. 加密数据
    let encrypted = cipher.update(data, 'utf8', 'hex')
    encrypted += cipher.final('hex')
    
    // 5. 获取认证标签
    const authTag = cipher.getAuthTag()
    
    return {
      encrypted,
      salt: salt.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      algorithm: this.algorithm
    }
  }
  
  async decryptSensitiveData(
    encryptedData: EncryptedData, 
    context?: string
  ): Promise<string> {
    // 1. 重建加密密钥
    const salt = Buffer.from(encryptedData.salt, 'hex')
    const key = crypto.pbkdf2Sync(
      this.masterKey,
      salt,
      this.keyDerivationIterations,
      32,
      'sha256'
    )
    
    // 2. 创建解密器
    const decipher = crypto.createDecipher(encryptedData.algorithm, key)
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'))
    decipher.setAAD(Buffer.from(context || '', 'utf8'))
    
    // 3. 解密数据
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8')
    decrypted += decipher.final('utf8')
    
    return decrypted
  }
}

// 密码安全处理
class PasswordSecurity {
  private readonly saltRounds = 12
  
  async hashPassword(password: string): Promise<string> {
    // 使用 bcrypt 进行密码哈希
    return bcrypt.hash(password, this.saltRounds)
  }
  
  async verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash)
  }
  
  generateSecurePassword(length: number = 16): string {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*'
    let password = ''
    
    for (let i = 0; i < length; i++) {
      const randomIndex = crypto.randomInt(0, charset.length)
      password += charset[randomIndex]
    }
    
    return password
  }
  
  async checkPasswordStrength(password: string): Promise<PasswordStrength> {
    const checks = {
      length: password.length >= 12,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      numbers: /\d/.test(password),
      symbols: /[!@#$%^&*(),.?":{}|<>]/.test(password),
      commonPassword: !(await this.isCommonPassword(password))
    }
    
    const score = Object.values(checks).filter(Boolean).length
    
    return {
      score,
      maxScore: 6,
      strength: this.getStrengthLevel(score),
      checks,
      suggestions: this.getImprovementSuggestions(checks)
    }
  }
  
  private async isCommonPassword(password: string): Promise<boolean> {
    // 检查常见密码列表
    const commonPasswords = await this.loadCommonPasswords()
    return commonPasswords.includes(password.toLowerCase())
  }
}
```

### 数据脱敏
```typescript
class DataMasking {
  static maskEmail(email: string): string {
    const [username, domain] = email.split('@')
    
    if (username.length <= 2) {
      return `${username[0]}***@${domain}`
    }
    
    const maskedUsername = username[0] + '*'.repeat(username.length - 2) + username[username.length - 1]
    return `${maskedUsername}@${domain}`
  }
  
  static maskPhoneNumber(phone: string): string {
    const cleaned = phone.replace(/\D/g, '')
    
    if (cleaned.length === 11) {
      return `${cleaned.slice(0, 3)}****${cleaned.slice(-4)}`
    }
    
    return phone.replace(/\d/g, '*')
  }
  
  static maskCreditCard(cardNumber: string): string {
    const cleaned = cardNumber.replace(/\D/g, '')
    
    if (cleaned.length === 16) {
      return `****-****-****-${cleaned.slice(-4)}`
    }
    
    return cardNumber.replace(/\d/g, '*')
  }
  
  static maskIdNumber(idNumber: string): string {
    if (idNumber.length === 18) {
      return `${idNumber.slice(0, 6)}********${idNumber.slice(-4)}`
    }
    
    return idNumber.replace(/./g, '*')
  }
  
  static maskSensitiveObject(obj: any, sensitiveFields: string[]): any {
    const masked = { ...obj }
    
    for (const field of sensitiveFields) {
      if (masked[field]) {
        if (field.includes('email')) {
          masked[field] = this.maskEmail(masked[field])
        } else if (field.includes('phone')) {
          masked[field] = this.maskPhoneNumber(masked[field])
        } else if (field.includes('card')) {
          masked[field] = this.maskCreditCard(masked[field])
        } else {
          masked[field] = '***'
        }
      }
    }
    
    return masked
  }
}
```

## API 安全

### API 安全中间件
```typescript
class APISecurityMiddleware {
  // 请求限流
  async rateLimiting(req: Request, res: Response, next: NextFunction): Promise<void> {
    const clientId = this.getClientIdentifier(req)
    const key = `rate_limit:${clientId}`
    
    const current = await this.redis.get(key)
    const limit = this.getRateLimit(req)
    
    if (current && parseInt(current) >= limit.requests) {
      res.status(429).json({
        error: 'Too Many Requests',
        retryAfter: limit.windowMs / 1000
      })
      return
    }
    
    // 增加计数
    await this.redis.multi()
      .incr(key)
      .expire(key, limit.windowMs / 1000)
      .exec()
    
    // 设置响应头
    res.set({
      'X-RateLimit-Limit': limit.requests.toString(),
      'X-RateLimit-Remaining': Math.max(0, limit.requests - (parseInt(current || '0') + 1)).toString(),
      'X-RateLimit-Reset': new Date(Date.now() + limit.windowMs).toISOString()
    })
    
    next()
  }
  
  // CORS 安全配置
  corsConfig(): CorsOptions {
    return {
      origin: (origin, callback) => {
        const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || []
        
        if (!origin || allowedOrigins.includes(origin)) {
          callback(null, true)
        } else {
          callback(new Error('Not allowed by CORS'))
        }
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
      exposedHeaders: ['X-Total-Count', 'X-Page-Count'],
      maxAge: 86400 // 24 hours
    }
  }
  
  // 安全头设置
  securityHeaders(req: Request, res: Response, next: NextFunction): void {
    res.set({
      // 防止 XSS 攻击
      'X-XSS-Protection': '1; mode=block',
      
      // 防止 MIME 类型嗅探
      'X-Content-Type-Options': 'nosniff',
      
      // 防止点击劫持
      'X-Frame-Options': 'DENY',
      
      // 强制 HTTPS
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
      
      // 内容安全策略
      'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'"
      ].join('; '),
      
      // 权限策略
      'Permissions-Policy': [
        'camera=()',
        'microphone=()',
        'geolocation=()',
        'payment=()'
      ].join(', '),
      
      // 引用策略
      'Referrer-Policy': 'strict-origin-when-cross-origin'
    })
    
    next()
  }
  
  // API 密钥验证
  async validateApiKey(req: Request, res: Response, next: NextFunction): Promise<void> {
    const apiKey = req.headers['x-api-key'] as string
    
    if (!apiKey) {
      res.status(401).json({ error: 'API key required' })
      return
    }
    
    const keyInfo = await this.apiKeyService.validateKey(apiKey)
    
    if (!keyInfo) {
      res.status(401).json({ error: 'Invalid API key' })
      return
    }
    
    if (keyInfo.isExpired) {
      res.status(401).json({ error: 'API key expired' })
      return
    }
    
    // 检查 API 密钥权限
    const hasPermission = await this.checkApiKeyPermission(keyInfo, req.path, req.method)
    
    if (!hasPermission) {
      res.status(403).json({ error: 'Insufficient API key permissions' })
      return
    }
    
    // 记录 API 使用情况
    await this.logApiUsage(keyInfo, req)
    
    req.apiKey = keyInfo
    next()
  }
}
```

### GraphQL 安全
```typescript
class GraphQLSecurity {
  // 查询复杂度限制
  createComplexityLimitRule(maxComplexity: number = 1000) {
    return depthLimit(maxComplexity, {
      onComplete: (complexity: number) => {
        console.log(`Query complexity: ${complexity}`)
      },
      createError: (max: number, actual: number) => {
        return new Error(`Query complexity ${actual} exceeds maximum ${max}`)
      }
    })
  }
  
  // 查询深度限制
  createDepthLimitRule(maxDepth: number = 10) {
    return depthLimit(maxDepth, {
      ignore: ['__schema', '__type']
    })
  }
  
  // 查询白名单
  createQueryWhitelist(allowedQueries: string[]) {
    return (req: Request, res: Response, next: NextFunction) => {
      const query = req.body.query
      
      if (!query) {
        return next()
      }
      
      const queryHash = crypto.createHash('sha256').update(query).digest('hex')
      
      if (!allowedQueries.includes(queryHash)) {
        return res.status(400).json({
          error: 'Query not in whitelist'
        })
      }
      
      next()
    }
  }
  
  // 字段级权限控制
  createFieldPermissionRule() {
    return (root: any, args: any, context: any, info: any) => {
      const fieldName = info.fieldName
      const user = context.user
      
      // 检查用户是否有权限访问该字段
      if (!this.hasFieldPermission(user, fieldName)) {
        throw new ForbiddenError(`Access denied to field: ${fieldName}`)
      }
      
      return true
    }
  }
}
```

## 日志和监控

### 安全日志记录
```typescript
class SecurityLogger {
  private logger: Logger
  
  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      transports: [
        new winston.transports.File({ 
          filename: 'logs/security.log',
          maxsize: 10485760, // 10MB
          maxFiles: 10
        }),
        new winston.transports.Console({
          format: winston.format.simple()
        })
      ]
    })
  }
  
  logAuthenticationAttempt(event: AuthEvent): void {
    this.logger.info('Authentication attempt', {
      type: 'auth_attempt',
      userId: event.userId,
      ip: event.ip,
      userAgent: event.userAgent,
      success: event.success,
      reason: event.reason,
      timestamp: new Date().toISOString()
    })
  }
  
  logAuthorizationFailure(event: AuthzEvent): void {
    this.logger.warn('Authorization failure', {
      type: 'authz_failure',
      userId: event.userId,
      resource: event.resource,
      action: event.action,
      ip: event.ip,
      timestamp: new Date().toISOString()
    })
  }
  
  logSecurityIncident(incident: SecurityIncident): void {
    this.logger.error('Security incident', {
      type: 'security_incident',
      severity: incident.severity,
      category: incident.category,
      description: incident.description,
      userId: incident.userId,
      ip: incident.ip,
      evidence: incident.evidence,
      timestamp: new Date().toISOString()
    })
    
    // 发送安全告警
    this.sendSecurityAlert(incident)
  }
  
  logDataAccess(event: DataAccessEvent): void {
    this.logger.info('Data access', {
      type: 'data_access',
      userId: event.userId,
      resource: event.resource,
      action: event.action,
      recordCount: event.recordCount,
      sensitiveData: event.containsSensitiveData,
      timestamp: new Date().toISOString()
    })
  }
  
  private async sendSecurityAlert(incident: SecurityIncident): Promise<void> {
    if (incident.severity === 'critical' || incident.severity === 'high') {
      // 发送即时告警
      await this.alertService.sendImmediate({
        title: `Security Incident: ${incident.category}`,
        message: incident.description,
        severity: incident.severity,
        metadata: incident
      })
    }
  }
}
```

### 异常检测
```typescript
class SecurityAnomalyDetector {
  async detectLoginAnomalies(userId: string, loginEvent: LoginEvent): Promise<AnomalyResult> {
    const anomalies: Anomaly[] = []
    
    // 1. 地理位置异常
    const locationAnomaly = await this.checkLocationAnomaly(userId, loginEvent.ip)
    if (locationAnomaly) {
      anomalies.push(locationAnomaly)
    }
    
    // 2. 时间异常
    const timeAnomaly = await this.checkTimeAnomaly(userId, loginEvent.timestamp)
    if (timeAnomaly) {
      anomalies.push(timeAnomaly)
    }
    
    // 3. 设备异常
    const deviceAnomaly = await this.checkDeviceAnomaly(userId, loginEvent.userAgent)
    if (deviceAnomaly) {
      anomalies.push(deviceAnomaly)
    }
    
    // 4. 频率异常
    const frequencyAnomaly = await this.checkFrequencyAnomaly(userId, loginEvent.timestamp)
    if (frequencyAnomaly) {
      anomalies.push(frequencyAnomaly)
    }
    
    const riskScore = this.calculateRiskScore(anomalies)
    
    return {
      anomalies,
      riskScore,
      requiresAdditionalAuth: riskScore > 0.7,
      recommendedActions: this.getRecommendedActions(riskScore, anomalies)
    }
  }
  
  private async checkLocationAnomaly(userId: string, ip: string): Promise<Anomaly | null> {
    const location = await this.geoService.getLocation(ip)
    const recentLocations = await this.getUserRecentLocations(userId, 30) // 30天内
    
    const isNewLocation = !recentLocations.some(loc => 
      this.calculateDistance(location, loc) < 100 // 100km内
    )
    
    if (isNewLocation) {
      return {
        type: 'location',
        severity: 'medium',
        description: `Login from new location: ${location.city}, ${location.country}`,
        confidence: 0.8
      }
    }
    
    return null
  }
  
  private async checkTimeAnomaly(userId: string, timestamp: Date): Promise<Anomaly | null> {
    const userTimezone = await this.getUserTimezone(userId)
    const localTime = new Date(timestamp.toLocaleString('en-US', { timeZone: userTimezone }))
    const hour = localTime.getHours()
    
    // 检查是否在异常时间登录 (凌晨2-6点)
    if (hour >= 2 && hour <= 6) {
      const recentNightLogins = await this.getRecentNightLogins(userId, 30)
      
      if (recentNightLogins.length < 3) { // 30天内夜间登录少于3次
        return {
          type: 'time',
          severity: 'low',
          description: `Unusual login time: ${hour}:00 (local time)`,
          confidence: 0.6
        }
      }
    }
    
    return null
  }
  
  private calculateRiskScore(anomalies: Anomaly[]): number {
    if (anomalies.length === 0) return 0
    
    const totalWeight = anomalies.reduce((sum, anomaly) => {
      const severityWeight = {
        low: 0.3,
        medium: 0.6,
        high: 0.9,
        critical: 1.0
      }[anomaly.severity]
      
      return sum + (severityWeight * anomaly.confidence)
    }, 0)
    
    return Math.min(totalWeight / anomalies.length, 1.0)
  }
}
```

这套安全开发规范涵盖了现代应用开发中的关键安全领域，通过多层防护和最佳实践，能够有效防范常见的安全威胁。
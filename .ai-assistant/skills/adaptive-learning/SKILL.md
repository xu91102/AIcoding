---
name: adaptive-learning
description: AI 自主学习系统，观察用户行为并自动优化工作模式
version: 1.0.0
platform: universal
---

# AI 自主学习系统

基于 everything-claude-code 的持续学习理念，为通用 AI 助手框架设计的智能学习系统。

## 核心理念

### 学习模型：行为模式 (Behavior Patterns)
```yaml
---
id: prefer-functional-programming
trigger: "编写 JavaScript/TypeScript 函数时"
confidence: 0.8
domain: "code-style"
source: "user-behavior"
created: "2026-02-01"
last_updated: "2026-02-01"
evidence_count: 12
---



## 观察证据
- 用户在 8 次代码编写中都选择了箭头函数
- 用户 3 次将类重构为函数
- 用户偏好使用 map/filter/reduce 而非 for 循环
- 符合 rules/coding-standards.md 的函数式原则

## 触发条件
- 文件类型：.js, .ts, .jsx, .tsx
- 场景：编写新函数或重构现有代码
- 上下文：业务逻辑实现

## 应用建议
当检测到用户编写函数时，主动建议：
- 使用箭头函数语法
- 优先考虑纯函数设计
- 使用函数式数组方法
- 避免可变状态操作
```

### 置信度演进系统
| 置信度 | 含义 | 行为 | 演进条件 |
|--------|------|------|----------|
| 0.3-0.4 | 初步观察 | 仅记录，不建议 | 观察到 3+ 次相似行为 |
| 0.5-0.6 | 趋势确认 | 温和提醒 | 用户未纠正 + 重复行为 |
| 0.7-0.8 | 强烈偏好 | 主动建议 | 持续正面反馈 |
| 0.9+ | 核心习惯 | 自动应用 | 长期稳定模式 |

## 学习机制

### 1. 观察层 (Observation Layer)
```javascript
// 用户行为观察
const behaviorObserver = {
  // 代码编写模式
  codeWritingPattern: {
    functionStyle: 'arrow', // arrow vs function
    variableDeclaration: 'const', // const vs let vs var
    errorHandling: 'try-catch', // try-catch vs callback
    asyncPattern: 'async-await' // async-await vs promise
  },
  
  // 工作流偏好
  workflowPreference: {
    testingApproach: 'tdd', // tdd vs test-after
    commitFrequency: 'frequent', // frequent vs batch
    reviewStyle: 'detailed', // detailed vs quick
    debuggingMethod: 'systematic' // systematic vs trial-error
  },
  
  // 架构选择
  architectureChoice: {
    componentSize: 'small', // small vs large
    abstraction: 'moderate', // high vs moderate vs low
    coupling: 'loose', // loose vs tight
    layering: 'strict' // strict vs flexible
  }
}
```

### 2. 分析层 (Analysis Layer)
```python
class PatternAnalyzer:
    def analyze_user_corrections(self, interactions):
        """分析用户纠正行为，识别偏好"""
        corrections = []
        
        for interaction in interactions:
            if interaction.type == 'user_correction':
                pattern = {
                    'from_style': interaction.original_suggestion,
                    'to_style': interaction.user_correction,
                    'context': interaction.context,
                    'frequency': self.count_similar_corrections(interaction)
                }
                corrections.append(pattern)
        
        return self.extract_preference_patterns(corrections)
    
    def detect_repeated_workflows(self, sessions):
        """检测重复的工作流程模式"""
        workflows = []
        
        for session in sessions:
            sequence = self.extract_action_sequence(session)
            if self.is_repeated_pattern(sequence):
                workflows.append({
                    'sequence': sequence,
                    'frequency': self.count_occurrences(sequence),
                    'success_rate': self.calculate_success_rate(sequence),
                    'context': session.context
                })
        
        return workflows
    
    def identify_tool_preferences(self, tool_usage):
        """识别工具使用偏好"""
        preferences = {}
        
        for tool_category, tools in tool_usage.items():
            most_used = max(tools, key=lambda t: t.usage_count)
            if most_used.usage_count > self.min_usage_threshold:
                preferences[tool_category] = {
                    'preferred_tool': most_used.name,
                    'confidence': most_used.usage_count / sum(t.usage_count for t in tools),
                    'context': most_used.typical_context
                }
        
        return preferences
```

### 3. 学习层 (Learning Layer)
```typescript
interface LearnedPattern {
  id: string
  domain: string
  trigger: string
  action: string
  confidence: number
  evidence: Evidence[]
  metadata: {
    created: Date
    lastUpdated: Date
    timesApplied: number
    userFeedback: 'positive' | 'negative' | 'neutral'
  }
}

class PatternLearner {
  async updatePattern(patternId: string, feedback: UserFeedback): Promise<void> {
    const pattern = await this.getPattern(patternId)
    
    // 根据反馈调整置信度
    if (feedback.type === 'positive') {
      pattern.confidence = Math.min(0.95, pattern.confidence + 0.05)
    } else if (feedback.type === 'negative') {
      pattern.confidence = Math.max(0.1, pattern.confidence - 0.1)
    }
    
    // 更新证据
    pattern.evidence.push({
      type: feedback.type,
      context: feedback.context,
      timestamp: new Date()
    })
    
    // 保存更新
    await this.savePattern(pattern)
    
    // 如果置信度过低，标记为待删除
    if (pattern.confidence < 0.2) {
      await this.markForDeletion(pattern)
    }
  }
  
  async suggestBasedOnContext(context: WorkContext): Promise<Suggestion[]> {
    const relevantPatterns = await this.findRelevantPatterns(context)
    const suggestions = []
    
    for (const pattern of relevantPatterns) {
      if (pattern.confidence >= this.config.suggestion_threshold) {
        suggestions.push({
          type: 'pattern_suggestion',
          message: `基于你的习惯，建议${pattern.action}`,
          confidence: pattern.confidence,
          pattern: pattern
        })
      }
    }
    
    return suggestions.sort((a, b) => b.confidence - a.confidence)
  }
}
```

## 学习领域

### 1. 代码风格学习
```yaml
# 函数式编程偏好
id: prefer-functional-style
domain: code-style
examples:
  - "用户总是选择 map() 而非 for 循环"
  - "用户将类重构为函数"
  - "用户偏好不可变数据操作"

# 命名规范偏好  
id: camelcase-preference
domain: code-style
examples:
  - "用户一致使用 camelCase 命名"
  - "用户纠正了 snake_case 建议"
  - "用户偏好描述性长名称"
```

### 2. 架构模式学习
```yaml
# 分层架构严格性
id: strict-layered-architecture
domain: architecture
examples:
  - "用户总是将业务逻辑从控制器中抽离"
  - "用户坚持数据访问层抽象"
  - "用户避免跨层直接调用"

# 组件大小偏好
id: small-component-preference  
domain: architecture
examples:
  - "用户将大组件拆分为小组件"
  - "用户偏好单一职责组件"
  - "用户限制组件行数在 100 行以内"
```

### 3. 工作流程学习
```yaml
# TDD 工作流偏好
id: tdd-workflow-preference
domain: workflow
examples:
  - "用户总是先写测试再写实现"
  - "用户遵循红-绿-重构循环"
  - "用户重视测试覆盖率"

# 频繁提交习惯
id: frequent-commit-habit
domain: workflow  
examples:
  - "用户每完成小功能就提交"
  - "用户提交信息详细规范"
  - "用户避免大批量提交"
```

### 4. 调试方法学习
```yaml
# 系统性调试方法
id: systematic-debugging
domain: debugging
examples:
  - "用户总是先查看日志"
  - "用户使用断点而非 console.log"
  - "用户创建最小复现案例"
  - "用户编写回归测试"
```

## 进化机制

### 模式聚合进化
```python
class PatternEvolution:
    def cluster_related_patterns(self, patterns: List[Pattern]) -> List[PatternCluster]:
        """将相关模式聚合成更高级的结构"""
        clusters = []
        
        # 按领域和相似度聚合
        for domain in self.domains:
            domain_patterns = [p for p in patterns if p.domain == domain]
            
            # 使用相似度算法聚合
            similarity_matrix = self.calculate_similarity_matrix(domain_patterns)
            clusters_in_domain = self.hierarchical_clustering(
                domain_patterns, 
                similarity_matrix,
                threshold=self.config.cluster_threshold
            )
            
            clusters.extend(clusters_in_domain)
        
        return clusters
    
    def evolve_to_skill(self, cluster: PatternCluster) -> Skill:
        """将模式集群进化为技能"""
        if len(cluster.patterns) >= 3 and cluster.avg_confidence >= 0.7:
            return Skill(
                name=f"{cluster.domain}-patterns",
                description=f"基于用户习惯学习的{cluster.domain}最佳实践",
                patterns=cluster.patterns,
                confidence=cluster.avg_confidence,
                source="learned_from_behavior"
            )
    
    def evolve_to_rule(self, pattern: Pattern) -> Rule:
        """将高置信度模式进化为规则"""
        if pattern.confidence >= 0.9 and pattern.evidence_count >= 10:
            return Rule(
                name=f"personal-{pattern.id}",
                description=f"个人偏好规则：{pattern.action}",
                enforcement_level="suggestion",  # suggestion vs warning vs error
                pattern=pattern,
                source="learned_preference"
            )
```

### 自动优化建议
```typescript
class AdaptiveOptimizer {
  async generateOptimizations(userProfile: UserProfile): Promise<Optimization[]> {
    const optimizations = []
    
    // 基于学习模式生成个性化规则
    const learnedPatterns = await this.getHighConfidencePatterns(userProfile)
    
    for (const pattern of learnedPatterns) {
      if (pattern.confidence >= 0.8) {
        optimizations.push({
          type: 'personal_rule',
          title: `个性化规则：${pattern.action}`,
          description: `基于你的 ${pattern.evidence_count} 次行为观察`,
          implementation: this.generateRuleImplementation(pattern),
          impact: 'medium',
          effort: 'low'
        })
      }
    }
    
    // 识别效率提升机会
    const inefficiencies = await this.detectInefficiencies(userProfile)
    
    for (const inefficiency of inefficiencies) {
      optimizations.push({
        type: 'workflow_optimization',
        title: `工作流优化：${inefficiency.area}`,
        description: `可以节省 ${inefficiency.time_saved} 分钟`,
        implementation: inefficiency.solution,
        impact: 'high',
        effort: 'medium'
      })
    }
    
    return optimizations.sort((a, b) => this.calculatePriority(b) - this.calculatePriority(a))
  }
}
```

## 实际应用示例

### 场景 1：代码风格学习
```markdown
## 观察阶段
用户连续 5 次将建议的类实现改为函数式实现：

```javascript
// AI 建议
class UserValidator {
  validate(user) { /* ... */ }
}

// 用户修改为
const validateUser = (user) => {
  // 函数式实现
}
```

## 学习结果
生成模式：prefer-functional-over-class
置信度：0.75
触发：当建议类设计时，优先推荐函数式方案
```

### 场景 2：工作流程学习
```markdown
## 观察阶段
用户的典型开发流程：
1. 先运行 `git status` 检查状态
2. 创建功能分支 `git checkout -b feature/xxx`
3. 编写测试用例
4. 实现功能代码
5. 运行测试确保通过
6. 提交代码 `git commit -m "feat: xxx"`

## 学习结果
生成工作流模式：tdd-with-git-flow
置信度：0.85
应用：在开始新功能时，主动提醒完整的 TDD + Git 流程
```

### 场景 3：架构偏好学习
```markdown
## 观察阶段
用户在 React 项目中的行为模式：
- 总是将业务逻辑抽离到 Custom Hooks
- 组件保持在 50 行以内
- 偏好组合而非继承
- 使用 TypeScript 严格模式

## 学习结果
生成架构模式：react-composition-pattern
置信度：0.88
应用：在 React 开发时，主动建议 Hooks 抽离和组件拆分
```

## 隐私和控制

### 数据保护
```json
{
  "privacy": {
    "data_retention": "30_days",
    "anonymization": true,
    "local_storage_only": true,
    "no_code_content": true,
    "pattern_only": true
  },
  "user_control": {
    "disable_learning": true,
    "delete_patterns": true,
    "export_patterns": true,
    "import_patterns": true,
    "adjust_thresholds": true
  }
}
```

### 透明度
- 用户可以查看所有学习到的模式
- 每个建议都标明来源和置信度
- 用户可以纠正或删除错误的模式
- 学习过程完全可控和可逆

这套自主学习系统让 AI 助手能够：
1. **观察**你的编程习惯和偏好
2. **学习**你的工作流程和模式
3. **适应**你的个人风格
4. **优化**协作效率和质量

通过持续学习，AI 助手会越来越懂你的需求，提供更加个性化和精准的帮助。
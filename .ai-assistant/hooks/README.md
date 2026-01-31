# AI 助手 Hooks 自动化系统

基于 everything-claude-code 的 Hooks 理念，为通用 AI 助手框架设计的自动化触发系统。

## 核心概念

### Hooks 是什么？
Hooks 是事件驱动的自动化机制，当特定条件满足时自动执行预定义的操作。

```
用户操作 → 触发条件 → Hook 执行 → AI 响应优化
```

### 支持的平台

| 平台 | Hook 支持 | 实现方式 |
|------|----------|----------|
| **Claude (Kiro)** | 原生支持 | JSON 配置文件 |
| **ChatGPT** | 手动触发 | 用户主动调用 |
| **Gemini** | 脚本模拟 | 外部脚本监控 |
| **通用平台** | 提醒机制 | 用户自主执行 |

## Hook 类型

### 1. 文件操作 Hooks
```json
{
  "file_hooks": {
    "on_file_edit": {
      "trigger": "文件被编辑时",
      "conditions": [
        "file_extension_matches",
        "file_size_check", 
        "content_pattern_match"
      ],
      "actions": [
        "code_quality_check",
        "style_validation",
        "security_scan"
      ]
    },
    "on_file_create": {
      "trigger": "新文件创建时",
      "actions": [
        "template_suggestion",
        "naming_validation",
        "structure_guidance"
      ]
    }
  }
}
```

### 2. 代码质量 Hooks
```json
{
  "quality_hooks": {
    "on_large_function": {
      "trigger": "函数超过 80 行",
      "action": "建议函数拆分",
      "severity": "warning"
    },
    "on_deep_nesting": {
      "trigger": "嵌套超过 4 层",
      "action": "建议重构逻辑",
      "severity": "error"
    },
    "on_magic_number": {
      "trigger": "检测到魔法数字",
      "action": "建议提取常量",
      "severity": "info"
    }
  }
}
```

### 3. 工作流 Hooks
```json
{
  "workflow_hooks": {
    "on_commit_prepare": {
      "trigger": "准备提交代码时",
      "actions": [
        "run_tests",
        "check_coverage",
        "validate_commit_message"
      ]
    },
    "on_pr_create": {
      "trigger": "创建 Pull Request 时", 
      "actions": [
        "generate_pr_template",
        "suggest_reviewers",
        "check_breaking_changes"
      ]
    }
  }
}
```

### 4. 学习 Hooks
```json
{
  "learning_hooks": {
    "on_user_correction": {
      "trigger": "用户纠正 AI 建议时",
      "action": "记录偏好模式",
      "update_confidence": -0.1
    },
    "on_repeated_action": {
      "trigger": "用户重复相同操作",
      "action": "识别工作流模式",
      "update_confidence": 0.05
    }
  }
}
```

## 平台适配实现

### Claude (Kiro) 原生实现
```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "tool == \"Edit\" && tool_input.path matches \"\\\\.(ts|tsx|js|jsx)$\"",
        "hooks": [
          {
            "type": "command",
            "command": "echo '[Hook] 前端代码已修改，建议检查组件设计原则' >&2"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "tool == \"Edit\" && tool_input.path matches \"\\\\.(py|java|go)$\"",
        "hooks": [
          {
            "type": "command", 
            "command": "echo '[Hook] 准备修改后端代码，请遵循分层架构原则' >&2"
          }
        ]
      }
    ]
  }
}
```

### ChatGPT 手动触发实现
```markdown
# 在每次代码修改后手动执行
请执行以下 Hook 检查：

## 文件类型检查
- 文件：{filename}
- 类型：{filetype}

## 自动检查项
1. **代码规模检查**：文件是否超过 600 行？
2. **函数大小检查**：是否有函数超过 80 行？
3. **复杂度检查**：是否有过深嵌套？
4. **安全检查**：是否有安全风险？

## 个性化建议
基于学习到的用户偏好，提供定制化建议。
```

### 通用平台脚本实现
```python
#!/usr/bin/env python3
"""
通用 AI 助手 Hooks 模拟器
适用于不支持原生 Hooks 的平台
"""

import os
import time
import json
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class AIAssistantHooks(FileSystemEventHandler):
    def __init__(self, config_path=".ai-assistant/hooks/config.json"):
        self.config = self.load_config(config_path)
        self.last_suggestions = {}
        
    def load_config(self, config_path):
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return self.get_default_config()
    
    def on_modified(self, event):
        if event.is_directory:
            return
            
        file_path = event.src_path
        file_ext = Path(file_path).suffix
        
        # 检查是否需要触发 Hook
        if self.should_trigger_hook(file_path, file_ext):
            suggestions = self.generate_suggestions(file_path)
            self.display_suggestions(suggestions)
    
    def should_trigger_hook(self, file_path, file_ext):
        # 检查文件类型
        if file_ext not in ['.py', '.js', '.ts', '.tsx', '.jsx', '.java', '.go']:
            return False
            
        # 检查忽略模式
        ignore_patterns = self.config.get('ignore_patterns', [])
        for pattern in ignore_patterns:
            if pattern in file_path:
                return False
                
        return True
    
    def generate_suggestions(self, file_path):
        suggestions = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.splitlines()
                
            # 文件大小检查
            if len(lines) > 600:
                suggestions.append({
                    'type': 'warning',
                    'message': f'文件过大 ({len(lines)} 行)，建议拆分',
                    'rule': 'basic-settings.md - 文件大小限制'
                })
            
            # 函数大小检查
            long_functions = self.find_long_functions(content)
            for func in long_functions:
                suggestions.append({
                    'type': 'warning',
                    'message': f'函数 {func["name"]} 过长 ({func["lines"]} 行)',
                    'rule': 'coding-standards.md - 函数大小限制'
                })
            
            # 代码风格检查
            style_issues = self.check_code_style(content, file_path)
            suggestions.extend(style_issues)
            
        except Exception as e:
            suggestions.append({
                'type': 'error',
                'message': f'文件分析失败: {e}'
            })
            
        return suggestions
    
    def find_long_functions(self, content):
        # 简化的函数长度检测
        functions = []
        lines = content.splitlines()
        
        in_function = False
        function_start = 0
        function_name = ""
        
        for i, line in enumerate(lines):
            # 检测函数开始（简化版）
            if any(keyword in line for keyword in ['function ', 'def ', 'async def']):
                if in_function:
                    # 结束上一个函数
                    func_lines = i - function_start
                    if func_lines > 80:
                        functions.append({
                            'name': function_name,
                            'lines': func_lines,
                            'start': function_start
                        })
                
                in_function = True
                function_start = i
                function_name = self.extract_function_name(line)
        
        return functions
    
    def check_code_style(self, content, file_path):
        issues = []
        lines = content.splitlines()
        
        for i, line in enumerate(lines, 1):
            # 检查行长度
            if len(line) > 120:
                issues.append({
                    'type': 'info',
                    'message': f'第 {i} 行过长 ({len(line)} 字符)',
                    'rule': 'coding-standards.md - 行长度限制'
                })
            
            # 检查魔法数字
            if self.has_magic_numbers(line):
                issues.append({
                    'type': 'info', 
                    'message': f'第 {i} 行可能包含魔法数字',
                    'rule': 'coding-standards.md - 避免魔法数字'
                })
        
        return issues
    
    def display_suggestions(self, suggestions):
        if not suggestions:
            return
            
        print("\n" + "="*50)
        print("🤖 AI 助手 Hook 建议")
        print("="*50)
        
        for suggestion in suggestions:
            icon = {
                'error': '❌',
                'warning': '⚠️', 
                'info': '💡'
            }.get(suggestion['type'], 'ℹ️')
            
            print(f"{icon} {suggestion['message']}")
            if 'rule' in suggestion:
                print(f"   📋 参考规则: {suggestion['rule']}")
        
        print("="*50 + "\n")

def main():
    hooks = AIAssistantHooks()
    observer = Observer()
    observer.schedule(hooks, ".", recursive=True)
    
    print("🚀 AI 助手 Hooks 监控已启动...")
    print("📁 监控目录: 当前工作目录")
    print("⏹️  按 Ctrl+C 停止监控\n")
    
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n👋 AI 助手 Hooks 监控已停止")
    
    observer.join()

if __name__ == "__main__":
    main()
```

## Hook 配置示例

### 完整的 Hooks 配置
```json
{
  "version": "1.0.0",
  "platform": "universal",
  "hooks": {
    "file_operations": {
      "on_edit": [
        {
          "name": "frontend_code_check",
          "matcher": "file_extension in ['.tsx', '.jsx', '.vue']",
          "actions": [
            {
              "type": "reminder",
              "message": "前端代码修改，请检查组件设计原则",
              "reference": "rules/coding-standards.md"
            },
            {
              "type": "check",
              "command": "check_component_size",
              "threshold": 100
            }
          ]
        },
        {
          "name": "backend_code_check", 
          "matcher": "file_extension in ['.py', '.java', '.go']",
          "actions": [
            {
              "type": "reminder",
              "message": "后端代码修改，请遵循分层架构",
              "reference": "rules/architecture-principles.md"
            }
          ]
        }
      ],
      "on_create": [
        {
          "name": "new_file_guidance",
          "matcher": "any",
          "actions": [
            {
              "type": "template_suggestion",
              "message": "为新文件提供模板建议"
            }
          ]
        }
      ]
    },
    "code_quality": {
      "on_large_file": {
        "trigger": "file_lines > 600",
        "action": {
          "type": "warning",
          "message": "文件过大，建议拆分为多个模块",
          "severity": "high"
        }
      },
      "on_long_function": {
        "trigger": "function_lines > 80",
        "action": {
          "type": "warning", 
          "message": "函数过长，建议拆分为更小的函数",
          "severity": "medium"
        }
      },
      "on_deep_nesting": {
        "trigger": "nesting_level > 4",
        "action": {
          "type": "error",
          "message": "嵌套过深，必须重构",
          "severity": "high"
        }
      }
    },
    "security": {
      "on_hardcoded_secret": {
        "trigger": "pattern_match: (password|api_key|secret)\\s*=\\s*['\"]",
        "action": {
          "type": "error",
          "message": "检测到硬编码密钥，必须移除",
          "severity": "critical"
        }
      },
      "on_sql_injection_risk": {
        "trigger": "pattern_match: (SELECT|INSERT|UPDATE|DELETE).*\\+.*",
        "action": {
          "type": "error",
          "message": "可能存在 SQL 注入风险，请使用参数化查询",
          "severity": "high"
        }
      }
    },
    "workflow": {
      "on_commit_prepare": [
        {
          "name": "pre_commit_check",
          "actions": [
            {
              "type": "check",
              "command": "run_tests",
              "message": "运行测试确保代码质量"
            },
            {
              "type": "check", 
              "command": "check_coverage",
              "message": "检查测试覆盖率"
            }
          ]
        }
      ]
    },
    "learning": {
      "on_user_correction": {
        "trigger": "user_corrects_suggestion",
        "action": {
          "type": "learn",
          "command": "update_preference_pattern",
          "confidence_delta": -0.1
        }
      },
      "on_repeated_pattern": {
        "trigger": "same_action_repeated >= 3",
        "action": {
          "type": "learn",
          "command": "create_behavior_pattern",
          "confidence_delta": 0.05
        }
      }
    }
  },
  "settings": {
    "enable_notifications": true,
    "notification_level": "warning",
    "auto_fix_suggestions": false,
    "learning_enabled": true,
    "ignore_patterns": [
      "node_modules/",
      ".git/",
      "*.log",
      "*.tmp"
    ]
  }
}
```

## 使用指南

### 1. Claude (Kiro) 用户
```bash
# 1. 复制 hooks 配置到项目
cp .ai-assistant/hooks/claude-hooks.json .claude/hooks.json

# 2. 或者在 settings.json 中引用
{
  "hooks": {
    "include": [".ai-assistant/hooks/claude-hooks.json"]
  }
}
```

### 2. ChatGPT 用户
```markdown
# 在每次代码修改后执行
请执行 AI 助手 Hook 检查：

**文件信息**：
- 文件名：{filename}
- 修改类型：{edit_type}

**检查项目**：
1. 按照 .ai-assistant/rules/coding-standards.md 检查代码规范
2. 应用 .ai-assistant/hooks/quality-checks.md 的质量标准
3. 基于学习到的个人偏好提供建议

**输出格式**：
- ✅ 符合标准的部分
- ⚠️ 需要改进的地方  
- ❌ 必须修复的问题
```

### 3. 通用平台用户
```bash
# 1. 安装依赖
pip install watchdog

# 2. 运行 Hook 监控
python .ai-assistant/hooks/universal-hooks.py

# 3. 或者手动触发检查
python .ai-assistant/hooks/manual-check.py --file=src/component.tsx
```

## 高级功能

### 1. 智能学习 Hooks
```python
class LearningHook:
    def on_user_interaction(self, interaction):
        """学习用户行为模式"""
        pattern = self.extract_pattern(interaction)
        
        if pattern.confidence > 0.7:
            # 生成个性化 Hook
            personal_hook = {
                "name": f"personal_{pattern.id}",
                "trigger": pattern.trigger,
                "action": pattern.preferred_action,
                "confidence": pattern.confidence
            }
            
            self.add_personal_hook(personal_hook)
    
    def suggest_workflow_optimization(self, user_history):
        """基于历史行为建议工作流优化"""
        inefficiencies = self.detect_inefficiencies(user_history)
        
        for inefficiency in inefficiencies:
            optimization_hook = {
                "trigger": inefficiency.context,
                "action": {
                    "type": "suggestion",
                    "message": f"建议使用 {inefficiency.better_approach}",
                    "time_saved": inefficiency.estimated_time_saved
                }
            }
            
            yield optimization_hook
```

### 2. 团队协作 Hooks
```json
{
  "team_hooks": {
    "on_pr_review": {
      "trigger": "pull_request_created",
      "actions": [
        {
          "type": "auto_assign_reviewers",
          "strategy": "expertise_based"
        },
        {
          "type": "generate_review_checklist", 
          "template": "team_review_template"
        }
      ]
    },
    "on_coding_standard_violation": {
      "trigger": "style_check_failed",
      "actions": [
        {
          "type": "team_notification",
          "message": "代码规范违反，需要团队关注"
        },
        {
          "type": "suggest_training",
          "topic": "coding_standards"
        }
      ]
    }
  }
}
```

### 3. 性能监控 Hooks
```json
{
  "performance_hooks": {
    "on_slow_function": {
      "trigger": "execution_time > 1000ms",
      "action": {
        "type": "performance_alert",
        "message": "检测到性能瓶颈，建议优化",
        "suggestions": [
          "添加缓存",
          "优化算法复杂度", 
          "使用异步处理"
        ]
      }
    },
    "on_memory_leak": {
      "trigger": "memory_usage_increasing",
      "action": {
        "type": "memory_alert",
        "message": "可能存在内存泄漏"
      }
    }
  }
}
```

这套 Hooks 系统让 AI 助手能够：

1. **实时响应**：在关键时刻自动提供帮助
2. **个性化**：基于学习适应用户习惯
3. **预防性**：在问题发生前给出警告
4. **效率提升**：自动化重复性检查工作

通过 Hooks，AI 助手从被动响应变为主动协助，大大提升开发效率和代码质量。
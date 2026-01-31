#!/usr/bin/env python3
"""
AI 助手行为观察器
观察用户与 AI 助手的交互，识别行为模式并学习用户偏好
"""

import json
import os
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import re

@dataclass
class Interaction:
    """用户交互记录"""
    id: str
    timestamp: datetime
    type: str  # 'user_input', 'ai_response', 'user_correction', 'file_operation'
    content: str
    context: Dict[str, Any]
    metadata: Dict[str, Any]

@dataclass
class BehaviorPattern:
    """行为模式"""
    id: str
    domain: str  # 'code-style', 'workflow', 'architecture', 'debugging'
    trigger: str
    action: str
    confidence: float
    evidence_count: int
    created: datetime
    last_updated: datetime
    evidence: List[Dict[str, Any]]

class BehaviorObserver:
    """行为观察器"""
    
    def __init__(self, config_path: str = ".ai-assistant/learning/config.json"):
        self.config_path = config_path
        self.config = self.load_config()
        self.interactions_dir = Path(".ai-assistant/learning/observations")
        self.patterns_dir = Path(".ai-assistant/learning/patterns")
        self.evolved_dir = Path(".ai-assistant/learning/evolved")
        
        # 确保目录存在
        for dir_path in [self.interactions_dir, self.patterns_dir, self.evolved_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
    
    def load_config(self) -> Dict[str, Any]:
        """加载配置"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            return self.get_default_config()
    
    def get_default_config(self) -> Dict[str, Any]:
        """默认配置"""
        return {
            "observation": {
                "enabled": True,
                "min_confidence_threshold": 0.3,
                "pattern_creation_threshold": 3,
                "max_observations_per_day": 1000
            },
            "learning": {
                "confidence_increment": 0.05,
                "confidence_decrement": 0.1,
                "max_confidence": 0.95,
                "min_confidence": 0.1
            },
            "domains": [
                "code-style",
                "workflow", 
                "architecture",
                "debugging",
                "testing",
                "performance"
            ]
        }
    
    def observe_interaction(self, interaction_type: str, content: str, context: Dict[str, Any] = None) -> str:
        """观察用户交互"""
        if not self.config["observation"]["enabled"]:
            return ""
        
        interaction = Interaction(
            id=self.generate_interaction_id(),
            timestamp=datetime.now(),
            type=interaction_type,
            content=content,
            context=context or {},
            metadata={}
        )
        
        # 保存交互记录
        self.save_interaction(interaction)
        
        # 分析交互模式
        patterns = self.analyze_interaction(interaction)
        
        # 更新现有模式
        for pattern in patterns:
            self.update_or_create_pattern(pattern)
        
        return interaction.id
    
    def analyze_interaction(self, interaction: Interaction) -> List[BehaviorPattern]:
        """分析交互，识别行为模式"""
        patterns = []
        
        if interaction.type == "user_correction":
            patterns.extend(self.analyze_user_correction(interaction))
        elif interaction.type == "code_modification":
            patterns.extend(self.analyze_code_modification(interaction))
        elif interaction.type == "workflow_action":
            patterns.extend(self.analyze_workflow_action(interaction))
        elif interaction.type == "architecture_decision":
            patterns.extend(self.analyze_architecture_decision(interaction))
        
        return patterns
    
    def analyze_user_correction(self, interaction: Interaction) -> List[BehaviorPattern]:
        """分析用户纠正行为"""
        patterns = []
        content = interaction.content.lower()
        
        # 代码风格偏好
        if "function" in content and "arrow" in content:
            patterns.append(BehaviorPattern(
                id="prefer-arrow-functions",
                domain="code-style",
                trigger="编写 JavaScript/TypeScript 函数时",
                action="优先使用箭头函数语法",
                confidence=0.3,
                evidence_count=1,
                created=datetime.now(),
                last_updated=datetime.now(),
                evidence=[{
                    "interaction_id": interaction.id,
                    "type": "user_correction",
                    "description": "用户将 function 声明改为箭头函数"
                }]
            ))
        
        # 命名规范偏好
        if "camelcase" in content or "snake_case" in content:
            naming_style = "camelCase" if "camelcase" in content else "snake_case"
            patterns.append(BehaviorPattern(
                id=f"prefer-{naming_style.lower().replace('_', '-')}-naming",
                domain="code-style",
                trigger="变量和函数命名时",
                action=f"使用 {naming_style} 命名规范",
                confidence=0.3,
                evidence_count=1,
                created=datetime.now(),
                last_updated=datetime.now(),
                evidence=[{
                    "interaction_id": interaction.id,
                    "type": "user_correction",
                    "description": f"用户偏好 {naming_style} 命名风格"
                }]
            ))
        
        return patterns
    
    def analyze_code_modification(self, interaction: Interaction) -> List[BehaviorPattern]:
        """分析代码修改行为"""
        patterns = []
        content = interaction.content
        
        # 函数式编程偏好
        if self.detect_functional_programming_pattern(content):
            patterns.append(BehaviorPattern(
                id="prefer-functional-programming",
                domain="code-style",
                trigger="编写数据处理逻辑时",
                action="优先使用函数式编程方法 (map/filter/reduce)",
                confidence=0.3,
                evidence_count=1,
                created=datetime.now(),
                last_updated=datetime.now(),
                evidence=[{
                    "interaction_id": interaction.id,
                    "type": "code_modification",
                    "description": "使用了函数式编程方法"
                }]
            ))
        
        # 类型安全偏好
        if self.detect_type_safety_pattern(content):
            patterns.append(BehaviorPattern(
                id="strict-type-safety",
                domain="code-style",
                trigger="编写 TypeScript 代码时",
                action="使用严格的类型定义，避免 any 类型",
                confidence=0.3,
                evidence_count=1,
                created=datetime.now(),
                last_updated=datetime.now(),
                evidence=[{
                    "interaction_id": interaction.id,
                    "type": "code_modification",
                    "description": "使用了严格的类型定义"
                }]
            ))
        
        return patterns
    
    def analyze_workflow_action(self, interaction: Interaction) -> List[BehaviorPattern]:
        """分析工作流程行为"""
        patterns = []
        content = interaction.content.lower()
        
        # TDD 工作流偏好
        if "test" in content and ("first" in content or "before" in content):
            patterns.append(BehaviorPattern(
                id="tdd-workflow-preference",
                domain="workflow",
                trigger="开发新功能时",
                action="遵循测试驱动开发流程",
                confidence=0.3,
                evidence_count=1,
                created=datetime.now(),
                last_updated=datetime.now(),
                evidence=[{
                    "interaction_id": interaction.id,
                    "type": "workflow_action",
                    "description": "先编写测试再实现功能"
                }]
            ))
        
        # 频繁提交习惯
        if "commit" in content and ("small" in content or "frequent" in content):
            patterns.append(BehaviorPattern(
                id="frequent-commit-habit",
                domain="workflow",
                trigger="完成功能模块时",
                action="频繁提交小的功能单元",
                confidence=0.3,
                evidence_count=1,
                created=datetime.now(),
                last_updated=datetime.now(),
                evidence=[{
                    "interaction_id": interaction.id,
                    "type": "workflow_action",
                    "description": "偏好频繁的小提交"
                }]
            ))
        
        return patterns
    
    def analyze_architecture_decision(self, interaction: Interaction) -> List[BehaviorPattern]:
        """分析架构决策行为"""
        patterns = []
        content = interaction.content.lower()
        
        # 分层架构偏好
        if "layer" in content and ("separate" in content or "clean" in content):
            patterns.append(BehaviorPattern(
                id="layered-architecture-preference",
                domain="architecture",
                trigger="设计系统架构时",
                action="严格遵循分层架构原则",
                confidence=0.3,
                evidence_count=1,
                created=datetime.now(),
                last_updated=datetime.now(),
                evidence=[{
                    "interaction_id": interaction.id,
                    "type": "architecture_decision",
                    "description": "选择分层架构设计"
                }]
            ))
        
        # 依赖注入偏好
        if "dependency" in content and "inject" in content:
            patterns.append(BehaviorPattern(
                id="dependency-injection-preference",
                domain="architecture",
                trigger="设计类和模块时",
                action="优先使用依赖注入模式",
                confidence=0.3,
                evidence_count=1,
                created=datetime.now(),
                last_updated=datetime.now(),
                evidence=[{
                    "interaction_id": interaction.id,
                    "type": "architecture_decision",
                    "description": "使用依赖注入模式"
                }]
            ))
        
        return patterns
    
    def detect_functional_programming_pattern(self, content: str) -> bool:
        """检测函数式编程模式"""
        functional_keywords = [
            r'\.map\(',
            r'\.filter\(',
            r'\.reduce\(',
            r'\.forEach\(',
            r'=>',
            r'const.*=.*\(',
            r'immutable',
            r'pure function'
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in functional_keywords)
    
    def detect_type_safety_pattern(self, content: str) -> bool:
        """检测类型安全模式"""
        type_safety_keywords = [
            r'interface\s+\w+',
            r'type\s+\w+\s*=',
            r':\s*\w+(\[\])?',
            r'<\w+>',
            r'as\s+\w+',
            r'typeof',
            r'keyof'
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in type_safety_keywords)
    
    def update_or_create_pattern(self, new_pattern: BehaviorPattern) -> None:
        """更新或创建行为模式"""
        existing_pattern = self.load_pattern(new_pattern.id)
        
        if existing_pattern:
            # 更新现有模式
            existing_pattern.evidence_count += 1
            existing_pattern.confidence = min(
                existing_pattern.confidence + self.config["learning"]["confidence_increment"],
                self.config["learning"]["max_confidence"]
            )
            existing_pattern.last_updated = datetime.now()
            existing_pattern.evidence.extend(new_pattern.evidence)
            
            # 保持证据数量在合理范围内
            if len(existing_pattern.evidence) > 20:
                existing_pattern.evidence = existing_pattern.evidence[-20:]
            
            self.save_pattern(existing_pattern)
        else:
            # 创建新模式
            self.save_pattern(new_pattern)
    
    def load_pattern(self, pattern_id: str) -> Optional[BehaviorPattern]:
        """加载行为模式"""
        pattern_file = self.patterns_dir / f"{pattern_id}.json"
        
        if not pattern_file.exists():
            return None
        
        try:
            with open(pattern_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # 转换日期字符串为 datetime 对象
            data['created'] = datetime.fromisoformat(data['created'])
            data['last_updated'] = datetime.fromisoformat(data['last_updated'])
            
            return BehaviorPattern(**data)
        except Exception as e:
            print(f"Error loading pattern {pattern_id}: {e}")
            return None
    
    def save_pattern(self, pattern: BehaviorPattern) -> None:
        """保存行为模式"""
        pattern_file = self.patterns_dir / f"{pattern.id}.json"
        
        # 转换为可序列化的字典
        data = asdict(pattern)
        data['created'] = pattern.created.isoformat()
        data['last_updated'] = pattern.last_updated.isoformat()
        
        try:
            with open(pattern_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving pattern {pattern.id}: {e}")
    
    def save_interaction(self, interaction: Interaction) -> None:
        """保存交互记录"""
        date_str = interaction.timestamp.strftime("%Y-%m-%d")
        interaction_file = self.interactions_dir / f"interactions-{date_str}.jsonl"
        
        # 转换为可序列化的字典
        data = asdict(interaction)
        data['timestamp'] = interaction.timestamp.isoformat()
        
        try:
            with open(interaction_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(data, ensure_ascii=False) + '\n')
        except Exception as e:
            print(f"Error saving interaction: {e}")
    
    def generate_interaction_id(self) -> str:
        """生成交互ID"""
        timestamp = str(time.time())
        return hashlib.md5(timestamp.encode()).hexdigest()[:12]
    
    def get_patterns_by_domain(self, domain: str) -> List[BehaviorPattern]:
        """获取指定领域的行为模式"""
        patterns = []
        
        for pattern_file in self.patterns_dir.glob("*.json"):
            pattern = self.load_pattern(pattern_file.stem)
            if pattern and pattern.domain == domain:
                patterns.append(pattern)
        
        return sorted(patterns, key=lambda p: p.confidence, reverse=True)
    
    def get_high_confidence_patterns(self, min_confidence: float = 0.7) -> List[BehaviorPattern]:
        """获取高置信度的行为模式"""
        patterns = []
        
        for pattern_file in self.patterns_dir.glob("*.json"):
            pattern = self.load_pattern(pattern_file.stem)
            if pattern and pattern.confidence >= min_confidence:
                patterns.append(pattern)
        
        return sorted(patterns, key=lambda p: p.confidence, reverse=True)
    
    def generate_learning_report(self) -> Dict[str, Any]:
        """生成学习报告"""
        all_patterns = []
        
        for pattern_file in self.patterns_dir.glob("*.json"):
            pattern = self.load_pattern(pattern_file.stem)
            if pattern:
                all_patterns.append(pattern)
        
        # 按领域分组
        patterns_by_domain = {}
        for pattern in all_patterns:
            if pattern.domain not in patterns_by_domain:
                patterns_by_domain[pattern.domain] = []
            patterns_by_domain[pattern.domain].append(pattern)
        
        # 统计信息
        total_patterns = len(all_patterns)
        high_confidence_patterns = len([p for p in all_patterns if p.confidence >= 0.8])
        avg_confidence = sum(p.confidence for p in all_patterns) / total_patterns if total_patterns > 0 else 0
        
        return {
            "summary": {
                "total_patterns": total_patterns,
                "high_confidence_patterns": high_confidence_patterns,
                "average_confidence": round(avg_confidence, 2),
                "active_domains": len(patterns_by_domain)
            },
            "patterns_by_domain": {
                domain: len(patterns) for domain, patterns in patterns_by_domain.items()
            },
            "top_patterns": [
                {
                    "id": p.id,
                    "domain": p.domain,
                    "confidence": p.confidence,
                    "evidence_count": p.evidence_count,
                    "trigger": p.trigger,
                    "action": p.action
                }
                for p in sorted(all_patterns, key=lambda x: x.confidence, reverse=True)[:10]
            ],
            "generated_at": datetime.now().isoformat()
        }
    
    def cleanup_old_interactions(self, days_to_keep: int = 30) -> None:
        """清理旧的交互记录"""
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        
        for interaction_file in self.interactions_dir.glob("interactions-*.jsonl"):
            try:
                date_str = interaction_file.stem.split('-', 1)[1]
                file_date = datetime.strptime(date_str, "%Y-%m-%d")
                
                if file_date < cutoff_date:
                    interaction_file.unlink()
                    print(f"Deleted old interaction file: {interaction_file}")
            except Exception as e:
                print(f"Error processing {interaction_file}: {e}")

def main():
    """主函数 - 用于测试和演示"""
    observer = BehaviorObserver()
    
    # 模拟一些交互
    print("🤖 AI 助手行为观察器启动")
    
    # 模拟用户纠正
    observer.observe_interaction(
        "user_correction",
        "请使用箭头函数而不是 function 声明",
        {"file_type": "typescript", "context": "function_definition"}
    )
    
    # 模拟代码修改
    observer.observe_interaction(
        "code_modification", 
        "const users = data.map(item => ({ id: item.id, name: item.name }))",
        {"file_type": "javascript", "operation": "data_transformation"}
    )
    
    # 模拟工作流行为
    observer.observe_interaction(
        "workflow_action",
        "先写测试用例，然后实现功能",
        {"phase": "development", "methodology": "tdd"}
    )
    
    # 生成学习报告
    report = observer.generate_learning_report()
    print("\n📊 学习报告:")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    
    # 获取高置信度模式
    high_confidence = observer.get_high_confidence_patterns(0.3)
    print(f"\n🎯 发现 {len(high_confidence)} 个行为模式:")
    for pattern in high_confidence:
        print(f"- {pattern.id}: {pattern.action} (置信度: {pattern.confidence:.2f})")

if __name__ == "__main__":
    main()
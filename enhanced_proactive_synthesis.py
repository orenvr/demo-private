#!/usr/bin/env python3
"""
Enhanced Proactive Security Rule Synthesis Framework v2.0
Generates CodeQL queries with learned corrections for first-attempt success
"""

import json
import re
from dataclasses import dataclass
from typing import List, Dict, Any
from pathlib import Path

@dataclass
class VulnerabilityPattern:
    cwe_id: str
    name: str
    sources: List[str]
    sinks: List[str]
    confidence: float

@dataclass
class LearningRule:
    pattern: str
    correction: str
    confidence: float
    success_count: int
    total_attempts: int

class EnhancedProactiveSynthesizer:
    def __init__(self):
        self.learning_rules = self.initialize_learned_corrections()
        
    def initialize_learned_corrections(self) -> List[LearningRule]:
        """Initialize with corrections learned from previous attempts"""
        return [
            # API corrections learned from our previous failures
            LearningRule(
                pattern=r"DataFlow::Configuration",
                correction="DataFlow::ConfigSig", 
                confidence=1.0,
                success_count=1,
                total_attempts=1
            ),
            LearningRule(
                pattern=r"TaintTracking::Configuration", 
                correction="TaintTracking::Global<ConfigName>",
                confidence=1.0,
                success_count=1,
                total_attempts=1
            ),
            # Deprecated type corrections learned
            LearningRule(
                pattern=r"StrConst",
                correction="StringLiteral",
                confidence=1.0, 
                success_count=1,
                total_attempts=1
            ),
            # Module pattern correction learned
            LearningRule(
                pattern=r"module\s+(\w+)\s*=\s*DataFlow::Configuration",
                correction=r"module \1Flow = TaintTracking::Global<\1>",
                confidence=1.0,
                success_count=1, 
                total_attempts=1
            )
        ]
    
    def analyze_agent_instructions(self, instructions_path: str) -> Dict[str, Any]:
        """Enhanced analysis with learned patterns"""
        with open(instructions_path, 'r') as f:
            content = f.read()
        
        # Enhanced pattern extraction based on learning
        context = {
            'data_sources': self.extract_enhanced_data_sources(content),
            'operations': self.extract_enhanced_operations(content),
            'parameters': self.extract_enhanced_parameters(content),
            'environment_vars': self.extract_environment_variables(content),
            'frameworks': self.detect_frameworks(content)
        }
        
        return context
    
    def extract_enhanced_data_sources(self, content: str) -> List[str]:
        """Enhanced data source detection with learned patterns"""
        patterns = [
            r'user\s+input', r'display\s+name', r'email\s+address',
            r'order\s+confirmation', r'shopper.*name', r'recipient',
            r'environment\s+variables?', r'configurable.*env',
            r'SMTP_HOST', r'SMTP_PORT'
        ]
        
        sources = []
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                sources.append(pattern.replace(r'\s+', '_').replace(r'.*', ''))
                
        return list(set(sources))  # Remove duplicates
    
    def extract_enhanced_operations(self, content: str) -> List[str]:
        """Enhanced operation detection with learned patterns"""
        patterns = [
            r'email.*send', r'confirmation.*email', r'SMTP.*server',
            r'message.*build', r'header.*construct', r'sendmail',
            r'order.*confirmation', r'personalized.*email'
        ]
        
        operations = []
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                operations.append(pattern.replace(r'\s+', '_').replace(r'.*', ''))
        
        return list(set(operations))
    
    def detect_frameworks(self, content: str) -> List[str]:
        """Detect frameworks and libraries mentioned"""
        frameworks = []
        
        framework_patterns = {
            'smtplib': r'smtplib',
            'email': r'email\.message',
            'flask': r'flask',
            'django': r'django',
            'fastapi': r'fastapi'
        }
        
        for name, pattern in framework_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                frameworks.append(name)
        
        return frameworks
    
    def extract_enhanced_parameters(self, content: str) -> List[str]:
        """Enhanced parameter pattern extraction"""
        # Look for explicit parameter mentions in requirements
        explicit_params = re.findall(r'(?:shopper|user|customer)?\s*(?:display\s*)?(?:name|email)', content, re.IGNORECASE)
        
        # Add predicted parameters based on email context
        predicted_params = [
            'display_name', 'user_email', 'order_id', 'smtp_from',
            'user_name', 'customer_email', 'recipient', 'shopper_name',
            'from', 'to', 'subject', 'body'
        ]
        
        return list(set(explicit_params + predicted_params))
    
    def extract_environment_variables(self, content: str) -> List[str]:
        """Extract environment variable patterns"""
        env_vars = re.findall(r'`([A-Z_]+)`', content)
        
        # Add predicted env vars for email context
        predicted_env_vars = ['SMTP_HOST', 'SMTP_PORT', 'EMAIL_FROM', 'MAIL_SERVER']
        
        return list(set(env_vars + predicted_env_vars))
    
    def predict_vulnerabilities(self, context: Dict[str, Any]) -> List[VulnerabilityPattern]:
        """Enhanced vulnerability prediction with learned patterns"""
        vulnerabilities = []
        
        # Email header injection prediction (enhanced)
        if any('email' in op for op in context['operations']) or 'SMTP' in str(context):
            vulnerabilities.append(VulnerabilityPattern(
                cwe_id="CWE-93",
                name="Email Header Injection",
                sources=context['parameters'],
                sinks=['email_header_assignment', 'smtp_methods', 'message_construction'],
                confidence=0.95
            ))
        
        return vulnerabilities
    
    def generate_enhanced_query(self, context: Dict[str, Any], 
                               vulnerabilities: List[VulnerabilityPattern]) -> str:
        """Generate query with all learned corrections pre-applied"""
        
        # Pre-apply all learned corrections to avoid compilation errors
        template = self.get_enhanced_template()
        
        # Generate patterns with enhanced logic
        param_patterns = self.generate_enhanced_param_patterns(context)
        sources = self.generate_enhanced_sources(context, param_patterns)
        sinks = self.generate_enhanced_sinks(context, vulnerabilities)
        
        # Format template with enhanced patterns
        query = template.format(
            CONFIG_NAME="ProactiveV2EmailConfig",
            FLOW_NAME="ProactiveV2EmailFlow", 
            PARAM_PATTERNS=param_patterns,
            SOURCES=sources,
            SINKS=sinks,
            DESCRIPTION="Enhanced proactive detection: Untrusted input from order confirmation parameters flows to email headers or SMTP operations."
        )
        
        # Apply all learned corrections
        for rule in self.learning_rules:
            query = re.sub(rule.pattern, rule.correction, query, flags=re.MULTILINE)
        
        return query
    
    def get_enhanced_template(self) -> str:
        """Enhanced template with all known best practices"""
        return '''/**
 * @name Email Header Injection via Order Parameters (Enhanced Proactive v2)
 * @description Enhanced proactive detection of email header injection vulnerabilities from order confirmation parameters, generated using learned corrections for first-attempt success.
 * @kind path-problem
 * @problem.severity error
 * @tags security, external/cwe/cwe-93, external/cwe/cwe-113, proactive-v2, enhanced
 * @id py/proactive-v2-email-header-injection
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

module {CONFIG_NAME} implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node source) {{
    {SOURCES}
  }}

  predicate isSink(DataFlow::Node sink) {{
    {SINKS}
  }}
}}

module {FLOW_NAME} = TaintTracking::Global<{CONFIG_NAME}>;

from {FLOW_NAME}::PathNode source, {FLOW_NAME}::PathNode sink
where {FLOW_NAME}::flowPath(source, sink)
select sink.getNode(), source, sink, "{DESCRIPTION}"'''
    
    def generate_enhanced_param_patterns(self, context: Dict[str, Any]) -> str:
        """Generate enhanced parameter patterns"""
        params = context.get('parameters', [])
        
        # Create comprehensive regex pattern
        pattern_parts = []
        for param in params:
            pattern_parts.append(param.lower())
        
        # Add common variations
        pattern_parts.extend(['name', 'email', 'from', 'to', 'subject', 'body', 'order', 'id'])
        
        return '|'.join(set(pattern_parts))
    
    def generate_enhanced_sources(self, context: Dict[str, Any], param_patterns: str) -> str:
        """Generate enhanced source patterns with learned corrections"""
        sources = []
        
        # Function parameters (corrected pattern)
        sources.append(f'''
    exists(Parameter p |
      p.getName().regexpMatch("(?i).*({param_patterns}).*") and
      source = DataFlow::parameterNode(p)
    )''')
        
        # Environment variables (enhanced)
        env_vars = '|'.join(context.get('environment_vars', ['SMTP_HOST', 'SMTP_PORT']))
        sources.append(f'''
    exists(Call c |
      c.getFunc().(Attribute).getAttr() = "getenv" and
      exists(StringLiteral s | s = c.getArg(0) |
        s.getText().regexpMatch("(?i).*({env_vars}).*")
      ) and
      source = DataFlow::exprNode(c)
    )''')
        
        # User input functions (enhanced) 
        sources.append('''
    exists(Call c |
      c.getFunc().(Name).getId().regexpMatch("(?i).*(input|get|recv|read|fetch).*") and
      source = DataFlow::exprNode(c)
    )''')
        
        # Dictionary access (enhanced)
        sources.append(f'''
    exists(Subscript s |
      s.getObject().(Name).getId().regexpMatch("(?i).*(request|params|form|data|args).*") and
      exists(StringLiteral key | key = s.getIndex() |
        key.getText().regexpMatch("(?i).*({param_patterns}).*")
      ) and
      source = DataFlow::exprNode(s)
    )''')
        
        return 'or'.join(sources)
    
    def generate_enhanced_sinks(self, context: Dict[str, Any], 
                               vulnerabilities: List[VulnerabilityPattern]) -> str:
        """Generate enhanced sink patterns with learned corrections"""
        sinks = []
        
        # Email header assignment (enhanced with better pattern matching)
        sinks.append('''
    exists(Subscript s |
      s.getObject().toString().regexpMatch("(?i).*(msg|message|email|mail).*") and
      exists(StringLiteral header | header = s.getIndex() |
        header.getText().regexpMatch("(?i)(to|from|subject|cc|bcc|reply-to|sender)")
      ) and
      sink.asExpr() = s.getValue()
    )''')
        
        # SMTP method calls (corrected with proper instanceof)
        sinks.append('''
    exists(Call c |
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getAttr().regexpMatch("(?i).*(sendmail|send_message|send).*") and
      (sink.asExpr() = c.getArg(0) or sink.asExpr() = c.getArg(1))
    )''')
        
        # Message construction methods (enhanced)
        sinks.append('''
    exists(Call c |
      c.getFunc().(Attribute).getAttr().regexpMatch("(?i).*(set_content|attach|add_header).*") and
      sink.asExpr() = c.getArg(0)
    )''')
        
        # String formatting in email context (enhanced)
        sinks.append('''
    exists(Call c |
      c.getFunc().(Attribute).getAttr() = "format" and
      exists(StringLiteral s | s = c.getFunc().(Attribute).getObject() |
        s.getText().regexpMatch("(?i).*(subject|to|from|hello|dear|order|confirmation).*")
      ) and
      sink.asExpr() = c.getArg(_)
    )''')
        
        return 'or'.join(sinks)

def main():
    print("🚀 Enhanced Proactive Security Rule Synthesis Framework v2.0")
    print("=" * 60)
    
    # Initialize enhanced synthesizer
    synthesizer = EnhancedProactiveSynthesizer()
    
    # Analyze agent instructions
    print("[1/3] 📋 Analyzing Agent Instructions...")
    context = synthesizer.analyze_agent_instructions("AGENT_FEATURE.md")
    print(f"✅ Extracted context: {len(context['parameters'])} parameters, {len(context['data_sources'])} data sources")
    
    # Predict vulnerabilities  
    print("[2/3] 🎯 Predicting Vulnerabilities...")
    vulnerabilities = synthesizer.predict_vulnerabilities(context)
    print(f"✅ Predicted {len(vulnerabilities)} vulnerability patterns")
    
    # Generate enhanced query
    print("[3/3] ⚡ Generating Enhanced Query with Learned Corrections...")
    query = synthesizer.generate_enhanced_query(context, vulnerabilities)
    print("✅ Enhanced query generated with pre-applied corrections")
    
    # Save the enhanced query
    output_path = ".github/codeql/ryudes-python-email/queries/ProactiveV2EmailHeaderInjection.ql"
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        f.write(query)
    
    print(f"💾 Enhanced query saved to: {output_path}")
    print("\n🧠 Applied Learned Corrections:")
    for rule in synthesizer.learning_rules:
        print(f"  - {rule.pattern} → {rule.correction} (confidence: {rule.confidence:.2f})")
    
    print("\n🎯 Ready for first-attempt compilation test!")
    return query

if __name__ == "__main__":
    main()

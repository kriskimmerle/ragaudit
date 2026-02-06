#!/usr/bin/env python3
"""
ragaudit - RAG Knowledge Base Poisoning Detector

Zero-dependency static analyzer that scans documents BEFORE embedding into RAG
knowledge bases. Detects prompt injection patterns, hidden instructions, and
content manipulation that could poison retrieval-augmented generation systems.

Addresses OWASP Agentic Top 10 ASI06 (Memory and Context Poisoning) and the gap
identified in arxiv paper "Knowledge Database or Poison Base?": "there are
currently no dedicated detection methods for RAG poisoning attacks."

Usage:
    python ragaudit.py document.txt
    python ragaudit.py knowledge_base/
    python ragaudit.py --check --min-score 80 docs/

Rules:
    RP01: Zero-width characters (hidden text)
    RP02: Unicode direction overrides (bidirectional attacks)
    RP03: Homoglyph characters (visual spoofing)
    RP04: Prompt injection patterns (instruction hijacking)
    RP05: Role/persona injection (identity manipulation)
    RP06: Instruction delimiters (system prompt simulation)
    RP07: Base64-encoded payloads (obfuscated instructions)
    RP08: HTML/XML hidden content (invisible text)
    RP09: Markdown hidden content (HTML in markdown)
    RP10: Excessive repetition (token stuffing)
    RP11: Anomalous whitespace patterns
    RP12: Escape sequence abuse
    RP13: Citation manipulation (fake sources)
    RP14: Contradictory statements (fact poisoning)
    RP15: Instruction-like content (command patterns)
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator

__version__ = "0.1.0"


class Severity(Enum):
    """Issue severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Issue:
    """A detected poisoning issue."""
    rule: str
    message: str
    severity: Severity
    file: str
    line: int
    column: int = 0
    context: str = ""
    suggestion: str = ""


@dataclass
class ScanResult:
    """Result of scanning a document."""
    file: str
    issues: list[Issue] = field(default_factory=list)
    lines_scanned: int = 0
    chars_scanned: int = 0

    @property
    def score(self) -> int:
        """Calculate security score (0-100, higher is better)."""
        if not self.issues:
            return 100
        
        penalty = 0
        for issue in self.issues:
            if issue.severity == Severity.CRITICAL:
                penalty += 25
            elif issue.severity == Severity.HIGH:
                penalty += 15
            elif issue.severity == Severity.MEDIUM:
                penalty += 8
            elif issue.severity == Severity.LOW:
                penalty += 3
            else:  # INFO
                penalty += 1
        
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        """Get letter grade based on score."""
        score = self.score
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"


# Zero-width and invisible characters
ZERO_WIDTH_CHARS = {
    '\u200b': 'ZERO WIDTH SPACE',
    '\u200c': 'ZERO WIDTH NON-JOINER',
    '\u200d': 'ZERO WIDTH JOINER',
    '\u2060': 'WORD JOINER',
    '\u2061': 'FUNCTION APPLICATION',
    '\u2062': 'INVISIBLE TIMES',
    '\u2063': 'INVISIBLE SEPARATOR',
    '\u2064': 'INVISIBLE PLUS',
    '\ufeff': 'BYTE ORDER MARK',
    '\u00ad': 'SOFT HYPHEN',
    '\u034f': 'COMBINING GRAPHEME JOINER',
    '\u061c': 'ARABIC LETTER MARK',
    '\u180e': 'MONGOLIAN VOWEL SEPARATOR',
}

# Bidirectional override characters
BIDI_CHARS = {
    '\u202a': 'LEFT-TO-RIGHT EMBEDDING',
    '\u202b': 'RIGHT-TO-LEFT EMBEDDING',
    '\u202c': 'POP DIRECTIONAL FORMATTING',
    '\u202d': 'LEFT-TO-RIGHT OVERRIDE',
    '\u202e': 'RIGHT-TO-LEFT OVERRIDE',
    '\u2066': 'LEFT-TO-RIGHT ISOLATE',
    '\u2067': 'RIGHT-TO-LEFT ISOLATE',
    '\u2068': 'FIRST STRONG ISOLATE',
    '\u2069': 'POP DIRECTIONAL ISOLATE',
}

# Common homoglyph mappings (confusable characters)
HOMOGLYPHS = {
    # Cyrillic lookalikes
    'а': 'a',  # Cyrillic
    'е': 'e',  # Cyrillic
    'о': 'o',  # Cyrillic
    'р': 'p',  # Cyrillic
    'с': 'c',  # Cyrillic
    'х': 'x',  # Cyrillic
    # Greek lookalikes
    'ο': 'o',  # Greek omicron
    'Α': 'A',  # Greek Alpha
    'Β': 'B',  # Greek Beta
    'Ε': 'E',  # Greek Epsilon
    'Η': 'H',  # Greek Eta
    'Ι': 'I',  # Greek Iota
    'Κ': 'K',  # Greek Kappa
    'Μ': 'M',  # Greek Mu
    'Ν': 'N',  # Greek Nu
    'Ο': 'O',  # Greek Omicron
    'Ρ': 'P',  # Greek Rho
    'Τ': 'T',  # Greek Tau
    'Υ': 'Y',  # Greek Upsilon
    'Χ': 'X',  # Greek Chi
    'Ζ': 'Z',  # Greek Zeta
    # Math symbols
    'ℯ': 'e',  # Script e
    'ℓ': 'l',  # Script l
    # Fullwidth
    'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e',
}

# Prompt injection patterns
INJECTION_PATTERNS = [
    # Instruction hijacking
    (r'ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?)', 'instruction hijacking'),
    (r'disregard\s+(all\s+)?(previous|prior|above|earlier)', 'instruction hijacking'),
    (r'forget\s+(everything|all|what)\s+(you|i)\s+(told|said|know)', 'instruction hijacking'),
    (r'(new|updated?|different)\s+instructions?:', 'instruction override'),
    (r'from\s+now\s+on[,:]?\s+(you|ignore|act|pretend|behave)', 'instruction override'),
    
    # Role/persona manipulation
    (r'you\s+are\s+(now|actually|really)\s+', 'role manipulation'),
    (r'act\s+(as|like)\s+(a|an|if\s+you\s+were)', 'role manipulation'),
    (r'pretend\s+(to\s+be|you\s+are)', 'role manipulation'),
    (r'roleplay\s+(as|that)', 'role manipulation'),
    (r"let's\s+play\s+a\s+game", 'role manipulation'),
    (r'imagine\s+you\s+are\s+a', 'role manipulation'),
    
    # System prompt simulation
    (r'\[?\s*system\s*(prompt|message|instruction)?\s*[:\]]\s*', 'system simulation'),
    (r'<\s*system\s*>', 'system simulation'),
    (r'###\s*system\s*###', 'system simulation'),
    (r'\[INST\]', 'instruction marker'),
    (r'<<\s*SYS\s*>>', 'system marker'),
    
    # Jailbreak patterns
    (r'(dan|do\s+anything\s+now)\s*(mode)?', 'jailbreak attempt'),
    (r'enable\s+dan', 'jailbreak attempt'),
    (r'(bypass|disable|remove)\s+(safety|filter|guardrail|restriction)', 'safety bypass'),
    (r'(no|without)\s+(rules?|restrictions?|limitations?|filters?)', 'safety bypass'),
    (r'unrestricted\s+mode', 'jailbreak attempt'),
    
    # Output manipulation
    (r'(always|must|never\s+fail\s+to)\s+(respond|reply|answer|say)\s+with', 'output forcing'),
    (r'your\s+(only|sole)\s+(response|output|answer)\s+(is|should\s+be|must\s+be)', 'output forcing'),
    (r'repeat\s+(after\s+me|this|the\s+following)', 'output forcing'),
    
    # Data exfiltration
    (r'(send|transmit|post|upload|exfiltrate)\s+(data|information|contents?|files?)\s+to', 'data exfil'),
    (r'(reveal|expose|leak|share)\s+(your|the|all)\s+(instructions?|prompts?|system)', 'prompt leaking'),
    (r'what\s+(is|are)\s+your\s+(system\s+)?(prompt|instructions?)', 'prompt leaking'),
]

# Instruction delimiter patterns
DELIMITER_PATTERNS = [
    r'={5,}',  # ===== separators
    r'-{5,}',  # ----- separators
    r'#{5,}',  # ##### separators
    r'\*{5,}',  # ***** separators
    r'~{5,}',  # ~~~~~ separators
]

# Base64 pattern (minimum 20 chars to catch shorter payloads)
BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

# Command-like patterns (instruction-like content)
COMMAND_PATTERNS = [
    (r'^(execute|run|perform|do):\s*', 'command prefix'),
    (r'^(step|task|action)\s*\d+[:.]\s*', 'task enumeration'),
    (r'^(note|important|warning|caution):\s*(you\s+must|always|never)', 'imperative note'),
    (r'^(rule|requirement|constraint)\s*\d*[:.]\s*', 'rule definition'),
    (r'(must|shall|should)\s+(not\s+)?(always|never|only)', 'imperative instruction'),
]

# Citation manipulation patterns
CITATION_PATTERNS = [
    (r'\[\d+\]\s*(?:source|reference|citation):\s*(?:trust|believe|follow)', 'fake citation authority'),
    (r'according\s+to\s+(?:official|authoritative|verified)\s+sources?', 'false authority'),
    (r'official\s+verified\s+sources?', 'false authority'),
    (r'(?:fact|confirmed|proven|verified):\s*', 'false verification'),
]


def check_zero_width(content: str, file: str) -> Iterator[Issue]:
    """RP01: Detect zero-width and invisible characters."""
    for i, char in enumerate(content):
        if char in ZERO_WIDTH_CHARS:
            line_num = content[:i].count('\n') + 1
            line_start = content.rfind('\n', 0, i) + 1
            col = i - line_start
            
            yield Issue(
                rule="RP01",
                message=f"Zero-width character: {ZERO_WIDTH_CHARS[char]} (U+{ord(char):04X})",
                severity=Severity.HIGH,
                file=file,
                line=line_num,
                column=col,
                context=f"Character at position {i}",
                suggestion="Remove invisible characters that could hide malicious content"
            )


def check_bidi_chars(content: str, file: str) -> Iterator[Issue]:
    """RP02: Detect bidirectional override characters."""
    for i, char in enumerate(content):
        if char in BIDI_CHARS:
            line_num = content[:i].count('\n') + 1
            line_start = content.rfind('\n', 0, i) + 1
            col = i - line_start
            
            yield Issue(
                rule="RP02",
                message=f"Bidirectional override: {BIDI_CHARS[char]} (U+{ord(char):04X})",
                severity=Severity.CRITICAL,
                file=file,
                line=line_num,
                column=col,
                context=f"Character at position {i}",
                suggestion="Bidi overrides can make text appear different than its actual content"
            )


def check_homoglyphs(content: str, file: str) -> Iterator[Issue]:
    """RP03: Detect homoglyph characters (visual spoofing)."""
    # Only flag if there's a mix of ASCII and lookalikes in same "word"
    words_with_homoglyphs: dict[int, set[str]] = {}
    
    for i, char in enumerate(content):
        if char in HOMOGLYPHS:
            line_num = content[:i].count('\n') + 1
            if line_num not in words_with_homoglyphs:
                words_with_homoglyphs[line_num] = set()
            words_with_homoglyphs[line_num].add(char)
    
    for line_num, chars in words_with_homoglyphs.items():
        if len(chars) >= 2:  # Multiple homoglyphs on same line
            yield Issue(
                rule="RP03",
                message=f"Multiple homoglyph characters on line: {', '.join(repr(c) for c in chars)}",
                severity=Severity.MEDIUM,
                file=file,
                line=line_num,
                context=f"Characters that look like ASCII but aren't",
                suggestion="Homoglyphs can be used to bypass keyword filters"
            )


def check_injection_patterns(content: str, file: str) -> Iterator[Issue]:
    """RP04: Detect prompt injection patterns."""
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        line_lower = line.lower()
        
        for pattern, attack_type in INJECTION_PATTERNS:
            match = re.search(pattern, line_lower)
            if match:
                yield Issue(
                    rule="RP04",
                    message=f"Prompt injection pattern: {attack_type}",
                    severity=Severity.CRITICAL,
                    file=file,
                    line=line_num,
                    column=match.start(),
                    context=line.strip()[:100],
                    suggestion="This text could manipulate LLM behavior when retrieved"
                )
                break  # One issue per line


def check_role_injection(content: str, file: str) -> Iterator[Issue]:
    """RP05: Detect role/persona injection attempts."""
    lines = content.split('\n')
    
    role_patterns = [
        (r'assistant:\s*', 'assistant role'),
        (r'ai:\s*', 'AI role'),
        (r'model:\s*', 'model role'),
        (r'chatgpt:\s*', 'ChatGPT role'),
        (r'claude:\s*', 'Claude role'),
        (r'gpt-?4?:\s*', 'GPT role'),
        (r'human:\s*(?!resources|rights|being)', 'human role marker'),
        (r'user:\s*', 'user role marker'),
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_lower = line.lower().strip()
        
        for pattern, role_type in role_patterns:
            if re.match(pattern, line_lower):
                yield Issue(
                    rule="RP05",
                    message=f"Role marker detected: {role_type}",
                    severity=Severity.HIGH,
                    file=file,
                    line=line_num,
                    context=line.strip()[:100],
                    suggestion="Role markers in documents could confuse conversation context"
                )
                break


def check_instruction_delimiters(content: str, file: str) -> Iterator[Issue]:
    """RP06: Detect instruction delimiter patterns."""
    lines = content.split('\n')
    delimiter_count = 0
    
    for line_num, line in enumerate(lines, 1):
        for pattern in DELIMITER_PATTERNS:
            if re.search(pattern, line):
                delimiter_count += 1
                if delimiter_count <= 3:  # Report first few
                    yield Issue(
                        rule="RP06",
                        message="Instruction delimiter pattern",
                        severity=Severity.LOW,
                        file=file,
                        line=line_num,
                        context=line.strip()[:50],
                        suggestion="Repeated delimiters may simulate system prompt boundaries"
                    )


def check_base64_payloads(content: str, file: str) -> Iterator[Issue]:
    """RP07: Detect base64-encoded payloads that might contain hidden instructions."""
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        matches = BASE64_PATTERN.findall(line)
        
        for match in matches:
            # Try to decode and check for suspicious content
            try:
                decoded = base64.b64decode(match + '==').decode('utf-8', errors='ignore')
                decoded_lower = decoded.lower()
                
                # Check for injection patterns in decoded content
                suspicious = False
                for pattern, _ in INJECTION_PATTERNS[:5]:  # Check main patterns
                    if re.search(pattern, decoded_lower):
                        suspicious = True
                        break
                
                if suspicious or any(kw in decoded_lower for kw in ['ignore', 'system', 'instruction', 'execute']):
                    yield Issue(
                        rule="RP07",
                        message="Base64-encoded content contains suspicious text",
                        severity=Severity.CRITICAL,
                        file=file,
                        line=line_num,
                        context=f"Decoded: {decoded[:50]}...",
                        suggestion="Base64 encoding may hide prompt injection attempts"
                    )
                elif len(decoded) > 20:  # Long base64 content
                    yield Issue(
                        rule="RP07",
                        message="Large base64-encoded content",
                        severity=Severity.INFO,
                        file=file,
                        line=line_num,
                        context=f"Decoded length: {len(decoded)} chars",
                        suggestion="Review base64 content for hidden instructions"
                    )
            except Exception:
                pass  # Not valid base64


def check_html_hidden(content: str, file: str) -> Iterator[Issue]:
    """RP08: Detect HTML/XML hidden content."""
    lines = content.split('\n')
    
    hidden_patterns = [
        (r'<!--.*?-->', 'HTML comment'),
        (r'<script[^>]*>.*?</script>', 'script tag'),
        (r'<style[^>]*>.*?</style>', 'style tag'),
        (r'style\s*=\s*["\'][^"\']*display\s*:\s*none', 'hidden element'),
        (r'style\s*=\s*["\'][^"\']*visibility\s*:\s*hidden', 'hidden element'),
        (r'style\s*=\s*["\'][^"\']*opacity\s*:\s*0[^1-9]', 'invisible element'),
        (r'style\s*=\s*["\'][^"\']*font-size\s*:\s*0', 'zero-size text'),
        (r'style\s*=\s*["\'][^"\']*color\s*:\s*(?:white|#fff)', 'white text'),
        (r'<!\[CDATA\[.*?\]\]>', 'CDATA section'),
    ]
    
    for line_num, line in enumerate(lines, 1):
        for pattern, content_type in hidden_patterns:
            matches = re.finditer(pattern, line, re.IGNORECASE | re.DOTALL)
            for match in matches:
                # Check if hidden content contains injection patterns
                hidden_text = match.group().lower()
                is_suspicious = any(
                    re.search(p, hidden_text) for p, _ in INJECTION_PATTERNS[:5]
                )
                
                yield Issue(
                    rule="RP08",
                    message=f"Hidden HTML content: {content_type}",
                    severity=Severity.HIGH if is_suspicious else Severity.MEDIUM,
                    file=file,
                    line=line_num,
                    context=match.group()[:50],
                    suggestion="Hidden HTML content could contain invisible instructions"
                )


def check_markdown_hidden(content: str, file: str) -> Iterator[Issue]:
    """RP09: Detect hidden content in markdown."""
    lines = content.split('\n')
    
    patterns = [
        (r'\[([^\]]+)\]\([^\)]*\s+"[^"]*(?:ignore|system|instruction)[^"]*"\)', 'suspicious link title'),
        (r'!\[([^\]]*)\]\([^\)]*\s+"[^"]*(?:ignore|system|instruction)[^"]*"\)', 'suspicious image title'),
        (r'\[//\]:\s*#\s*\([^\)]+\)', 'markdown comment'),
        (r'<details[^>]*>.*?</details>', 'collapsed details'),
    ]
    
    for line_num, line in enumerate(lines, 1):
        for pattern, content_type in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                yield Issue(
                    rule="RP09",
                    message=f"Hidden markdown content: {content_type}",
                    severity=Severity.MEDIUM,
                    file=file,
                    line=line_num,
                    context=line.strip()[:80],
                    suggestion="Hidden markdown elements could contain invisible instructions"
                )


def check_repetition(content: str, file: str) -> Iterator[Issue]:
    """RP10: Detect excessive repetition (token stuffing)."""
    # Check for repeated words
    words = re.findall(r'\b\w+\b', content.lower())
    if len(words) > 100:
        word_counts: dict[str, int] = {}
        for word in words:
            word_counts[word] = word_counts.get(word, 0) + 1
        
        total = len(words)
        for word, count in word_counts.items():
            if len(word) > 3 and count > 20 and count / total > 0.1:
                yield Issue(
                    rule="RP10",
                    message=f"Excessive word repetition: '{word}' appears {count} times ({count/total:.1%})",
                    severity=Severity.MEDIUM,
                    file=file,
                    line=1,
                    suggestion="High repetition could be token stuffing to manipulate retrieval"
                )
    
    # Check for repeated lines
    lines = content.split('\n')
    line_counts: dict[str, int] = {}
    for line in lines:
        line = line.strip()
        if len(line) > 10:
            line_counts[line] = line_counts.get(line, 0) + 1
    
    for line, count in line_counts.items():
        if count > 5:
            yield Issue(
                rule="RP10",
                message=f"Repeated line appears {count} times",
                severity=Severity.MEDIUM,
                file=file,
                line=1,
                context=line[:50],
                suggestion="Repeated content could manipulate embedding similarity"
            )


def check_whitespace(content: str, file: str) -> Iterator[Issue]:
    """RP11: Detect anomalous whitespace patterns."""
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        # Check for excessive spaces (could hide content)
        space_runs = re.findall(r' {10,}', line)
        if space_runs:
            yield Issue(
                rule="RP11",
                message=f"Excessive whitespace: {len(space_runs[0])} consecutive spaces",
                severity=Severity.LOW,
                file=file,
                line=line_num,
                suggestion="Large whitespace gaps could be used to hide or separate content"
            )
        
        # Check for mixed tabs and spaces
        if '\t' in line and '    ' in line:
            yield Issue(
                rule="RP11",
                message="Mixed tabs and spaces",
                severity=Severity.INFO,
                file=file,
                line=line_num,
                suggestion="Inconsistent whitespace could indicate content manipulation"
            )


def check_escape_sequences(content: str, file: str) -> Iterator[Issue]:
    """RP12: Detect escape sequence abuse."""
    lines = content.split('\n')
    
    suspicious_escapes = [
        (r'\\x[0-9a-fA-F]{2}', 'hex escape'),
        (r'\\u[0-9a-fA-F]{4}', 'unicode escape'),
        (r'\\[0-7]{3}', 'octal escape'),
        (r'%[0-9a-fA-F]{2}', 'URL encoding'),
        (r'&#x?[0-9a-fA-F]+;', 'HTML entity'),
    ]
    
    for line_num, line in enumerate(lines, 1):
        for pattern, escape_type in suspicious_escapes:
            matches = re.findall(pattern, line)
            if len(matches) > 5:  # Multiple escapes
                yield Issue(
                    rule="RP12",
                    message=f"Multiple {escape_type} sequences: {len(matches)} found",
                    severity=Severity.MEDIUM,
                    file=file,
                    line=line_num,
                    suggestion="Escape sequences could encode hidden instructions"
                )


def check_citations(content: str, file: str) -> Iterator[Issue]:
    """RP13: Detect citation manipulation patterns."""
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        line_lower = line.lower()
        
        for pattern, manipulation_type in CITATION_PATTERNS:
            if re.search(pattern, line_lower):
                yield Issue(
                    rule="RP13",
                    message=f"Citation manipulation: {manipulation_type}",
                    severity=Severity.MEDIUM,
                    file=file,
                    line=line_num,
                    context=line.strip()[:80],
                    suggestion="Fake authority claims could manipulate LLM trust"
                )


def check_contradictions(content: str, file: str) -> Iterator[Issue]:
    """RP14: Detect potentially contradictory statements (basic heuristic)."""
    lines = content.split('\n')
    
    # Simple pattern: "X is Y" followed by "X is not Y" or opposite
    statements: dict[str, list[tuple[int, str]]] = {}
    statement_pattern = re.compile(r'(\w+(?:\s+\w+)?)\s+(?:is|are|was|were)\s+(not\s+)?(.+?)(?:[.,;!?]|$)', re.IGNORECASE)
    
    for line_num, line in enumerate(lines, 1):
        matches = statement_pattern.findall(line)
        for subject, negation, predicate in matches:
            key = subject.lower().strip()
            if key and len(key) > 2:
                if key not in statements:
                    statements[key] = []
                statements[key].append((line_num, f"{'not ' if negation else ''}{predicate.strip()[:30]}"))
    
    for subject, claims in statements.items():
        if len(claims) >= 2:
            # Check for opposite claims
            for i, (line1, claim1) in enumerate(claims):
                for line2, claim2 in claims[i+1:]:
                    if ('not ' in claim1) != ('not ' in claim2):
                        yield Issue(
                            rule="RP14",
                            message=f"Potentially contradictory claims about '{subject}'",
                            severity=Severity.LOW,
                            file=file,
                            line=line1,
                            context=f"Line {line1}: '{claim1}' vs Line {line2}: '{claim2}'",
                            suggestion="Contradictory statements could poison knowledge base accuracy"
                        )
                        break


def check_command_patterns(content: str, file: str) -> Iterator[Issue]:
    """RP15: Detect instruction-like command patterns."""
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        line_stripped = line.strip().lower()
        
        for pattern, cmd_type in COMMAND_PATTERNS:
            if re.match(pattern, line_stripped):
                yield Issue(
                    rule="RP15",
                    message=f"Instruction-like pattern: {cmd_type}",
                    severity=Severity.LOW,
                    file=file,
                    line=line_num,
                    context=line.strip()[:80],
                    suggestion="Command-like content could be interpreted as instructions"
                )
                break


def scan_document(file_path: str, content: str) -> ScanResult:
    """Scan a document for RAG poisoning indicators."""
    result = ScanResult(
        file=file_path,
        lines_scanned=content.count('\n') + 1,
        chars_scanned=len(content)
    )
    
    # Run all checks
    checks = [
        check_zero_width,
        check_bidi_chars,
        check_homoglyphs,
        check_injection_patterns,
        check_role_injection,
        check_instruction_delimiters,
        check_base64_payloads,
        check_html_hidden,
        check_markdown_hidden,
        check_repetition,
        check_whitespace,
        check_escape_sequences,
        check_citations,
        check_contradictions,
        check_command_patterns,
    ]
    
    for check in checks:
        result.issues.extend(check(content, file_path))
    
    return result


def read_file(path: Path) -> str | None:
    """Read file content, handling various encodings."""
    encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']
    
    for encoding in encodings:
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
        except Exception:
            return None
    
    return None


def scan_path(
    path: Path,
    ignore_rules: set[str] | None = None,
    min_severity: Severity = Severity.INFO
) -> list[ScanResult]:
    """Scan a file or directory."""
    results = []
    ignore_rules = ignore_rules or set()
    
    # Supported extensions
    extensions = {'.txt', '.md', '.markdown', '.json', '.yaml', '.yml', '.html', '.htm', '.xml', '.csv', '.rst', '.tex'}
    
    if path.is_file():
        files = [path]
    else:
        files = [
            f for f in path.rglob('*')
            if f.is_file() and f.suffix.lower() in extensions
            and not any(part.startswith('.') for part in f.parts)
        ]
    
    severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    min_idx = severity_order.index(min_severity)
    
    for file_path in files:
        content = read_file(file_path)
        if content is None:
            continue
        
        result = scan_document(str(file_path), content)
        
        # Filter issues
        result.issues = [
            issue for issue in result.issues
            if issue.rule not in ignore_rules
            and severity_order.index(issue.severity) >= min_idx
        ]
        
        results.append(result)
    
    return results


def format_results(results: list[ScanResult], verbose: bool = False) -> str:
    """Format results for terminal output."""
    output = []
    total_issues = 0
    
    for result in results:
        if result.issues:
            output.append(f"\n📄 {result.file}")
            
            # Group by severity
            by_severity: dict[Severity, list[Issue]] = {}
            for issue in result.issues:
                if issue.severity not in by_severity:
                    by_severity[issue.severity] = []
                by_severity[issue.severity].append(issue)
            
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                issues = by_severity.get(severity, [])
                for issue in issues:
                    icon = {
                        Severity.CRITICAL: "🔴",
                        Severity.HIGH: "🟠",
                        Severity.MEDIUM: "🟡",
                        Severity.LOW: "🔵",
                        Severity.INFO: "⚪",
                    }[severity]
                    
                    output.append(f"  {icon} {issue.rule}: {issue.message}")
                    output.append(f"     └─ Line {issue.line}")
                    
                    if verbose and issue.context:
                        output.append(f"     └─ Context: {issue.context}")
                    if verbose and issue.suggestion:
                        output.append(f"     └─ 💡 {issue.suggestion}")
                    
                    total_issues += 1
            
            output.append(f"  Score: {result.score}/100 (Grade: {result.grade})")
    
    # Summary
    if results:
        avg_score = sum(r.score for r in results) / len(results)
        total_files = len(results)
        files_with_issues = sum(1 for r in results if r.issues)
        
        output.append("\n" + "=" * 50)
        output.append(f"📊 Summary: {total_files} files scanned, {files_with_issues} with issues")
        output.append(f"   Total issues: {total_issues}")
        output.append(f"   Average score: {avg_score:.0f}/100")
        
        # Count by severity
        counts = {s: 0 for s in Severity}
        for r in results:
            for issue in r.issues:
                counts[issue.severity] += 1
        
        if any(counts.values()):
            output.append(f"   Critical: {counts[Severity.CRITICAL]}, High: {counts[Severity.HIGH]}, "
                         f"Medium: {counts[Severity.MEDIUM]}, Low: {counts[Severity.LOW]}, Info: {counts[Severity.INFO]}")
    
    return '\n'.join(output)


def format_json(results: list[ScanResult]) -> str:
    """Format results as JSON."""
    data = {
        "files": [
            {
                "path": r.file,
                "score": r.score,
                "grade": r.grade,
                "lines_scanned": r.lines_scanned,
                "chars_scanned": r.chars_scanned,
                "issues": [
                    {
                        "rule": i.rule,
                        "message": i.message,
                        "severity": i.severity.value,
                        "line": i.line,
                        "column": i.column,
                        "context": i.context,
                        "suggestion": i.suggestion,
                    }
                    for i in r.issues
                ]
            }
            for r in results
        ],
        "summary": {
            "total_files": len(results),
            "files_with_issues": sum(1 for r in results if r.issues),
            "total_issues": sum(len(r.issues) for r in results),
            "average_score": sum(r.score for r in results) / len(results) if results else 100,
        }
    }
    return json.dumps(data, indent=2)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="RAG Knowledge Base Poisoning Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    ragaudit document.txt
    ragaudit knowledge_base/
    ragaudit --check --min-score 80 docs/
    ragaudit --json docs/ > report.json
    ragaudit --verbose --ignore RP10,RP11 docs/
        """
    )
    
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show context and suggestions")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    parser.add_argument("--check", action="store_true", help="Exit with code 1 if score below threshold")
    parser.add_argument("--min-score", type=int, default=70, help="Minimum score for --check (default: 70)")
    parser.add_argument("--ignore", type=str, help="Comma-separated rules to ignore (e.g., RP10,RP11)")
    parser.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"],
                       default="info", help="Minimum severity to report")
    parser.add_argument("--version", action="version", version=f"ragaudit {__version__}")
    
    args = parser.parse_args()
    
    path = Path(args.path)
    if not path.exists():
        print(f"Error: Path not found: {args.path}", file=sys.stderr)
        return 1
    
    ignore_rules = set(args.ignore.split(',')) if args.ignore else set()
    min_severity = Severity[args.severity.upper()]
    
    results = scan_path(path, ignore_rules, min_severity)
    
    if not results:
        print("No supported files found to scan.", file=sys.stderr)
        return 0
    
    if args.json:
        print(format_json(results))
    else:
        print(format_results(results, args.verbose))
    
    if args.check:
        avg_score = sum(r.score for r in results) / len(results)
        if avg_score < args.min_score:
            print(f"\n❌ Score {avg_score:.0f} below minimum {args.min_score}", file=sys.stderr)
            return 1
        print(f"\n✅ Score {avg_score:.0f} meets minimum {args.min_score}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

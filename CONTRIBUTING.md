# Contributing to ragaudit

Thank you for your interest in contributing to ragaudit! This document provides guidelines and instructions for contributing.

## Project Mission

ragaudit is a zero-dependency Python static analyzer that scans documents BEFORE embedding into RAG knowledge bases. We detect prompt injection, hidden instructions, and content manipulation that could poison retrieval-augmented generation systems. We prioritize:

- **Precision over recall** - minimize false positives
- **Zero dependencies** - uses only Python stdlib
- **Pre-embedding detection** - catch poisoning before it enters the knowledge base
- **RAG-specific patterns** - focus on attacks unique to retrieval systems

## Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/kriskimmerle/ragaudit.git
   cd ragaudit
   ```

2. **Install development dependencies**
   ```bash
   pip install pytest
   ```

3. **Run tests**
   ```bash
   python -m pytest test_ragaudit.py -v
   ```

4. **Test the CLI**
   ```bash
   python ragaudit.py demo_poisoned.txt
   ```

## Adding New Detection Rules

To add a new poisoning check:

1. **Identify the pattern**
   - What specific RAG poisoning technique does this catch?
   - Has it been demonstrated in research (cite the paper)?
   - Does it produce false positives on legitimate content?

2. **Choose a rule ID**
   - Use the next available RP## number (currently RP16+)
   - Update the README.md table with the new rule

3. **Implement the check**
   - Add a method to the `DocumentScanner` class in `ragaudit.py`
   - Pattern should be added to `scan_document()` workflow
   - Provide clear error messages and remediation suggestions

4. **Write tests**
   - Add test cases to `test_ragaudit.py`
   - Test both positive (should detect) and negative (should not detect) cases
   - Include edge cases and real-world examples

5. **Update documentation**
   - Add the rule to README.md detection rules table
   - Include severity, description, and example
   - Cite research if applicable (ASI06, RAG poisoning papers, etc.)

### Current Detection Rules (RP01-RP15)

- **RP01**: Zero-width characters (hidden text)
- **RP02**: Unicode direction overrides (bidirectional attacks)
- **RP03**: Homoglyph characters (visual spoofing)
- **RP04**: Prompt injection patterns (instruction hijacking)
- **RP05**: Role/persona injection (identity manipulation)
- **RP06**: Instruction delimiters (system prompt simulation)
- **RP07**: Base64-encoded payloads (obfuscated instructions)
- **RP08**: HTML/XML hidden content (invisible text)
- **RP09**: Markdown hidden content (HTML in markdown)
- **RP10**: Excessive repetition (token stuffing)
- **RP11**: Anomalous whitespace patterns
- **RP12**: Escape sequence abuse
- **RP13**: Citation manipulation (fake sources)
- **RP14**: Contradictory statements (fact poisoning)
- **RP15**: Instruction-like content (command patterns)

### Example Rule Implementation

```python
def _check_rp16_example_pattern(self, content: str, filename: str) -> Iterator[Issue]:
    """RP16: Example new poisoning pattern."""
    pattern = re.compile(r'malicious_pattern', re.IGNORECASE | re.MULTILINE)
    
    for match in pattern.finditer(content):
        line_num = content[:match.start()].count('\n') + 1
        context = self._get_context(content, match.start())
        
        yield Issue(
            rule="RP16",
            message="Example poisoning pattern detected",
            severity=Severity.HIGH,
            file=filename,
            line=line_num,
            context=context,
            suggestion="Remove or sanitize the pattern"
        )
```

### Example Test Case

```python
def test_rp16_example_pattern():
    """Test RP16: Example pattern detection."""
    scanner = DocumentScanner()
    content = "This contains malicious_pattern"
    issues = list(scanner._check_rp16_example_pattern(content, "test.txt"))
    
    assert len(issues) == 1
    assert issues[0].rule == "RP16"
    assert issues[0].severity == Severity.HIGH
    assert "example poisoning" in issues[0].message.lower()
```

## Code Style

- **Follow PEP 8** - use standard Python conventions
- **Type hints** - use modern type hints (e.g., `list[str]` not `List[str]`)
- **Comments** - explain *why*, not *what*
- **Docstrings** - required for public methods and classes

## Testing Guidelines

- **Test coverage** - aim for >90% coverage of new code
- **Test both cases** - positive (should detect) and negative (shouldn't)
- **Edge cases** - test boundary conditions
- **Real-world content** - use realistic document examples, not toy data

Run tests:
```bash
python -m pytest test_ragaudit.py -v
```

## Commit Guidelines

- **Clear messages** - describe what and why
- **One logical change per commit**
- **Reference issues** - use "Fixes #123" in commit messages

Example:
```
Add RP16: Detect adversarial retrieval patterns

Implements detection for retrieval-time attacks where malicious
content includes patterns designed to rank higher in similarity
search, based on findings in [Paper Name].

Fixes #123
```

## Pull Request Process

1. **Fork the repository** and create a feature branch
   ```bash
   git checkout -b feature/add-rp16-rule
   ```

2. **Make your changes**
   - Implement the feature or fix
   - Write tests
   - Update documentation

3. **Test locally**
   ```bash
   python -m pytest test_ragaudit.py -v
   python ragaudit.py demo_poisoned.txt  # Should still detect existing issues
   ```

4. **Submit a pull request**
   - Describe the change and motivation
   - Reference any related issues or research papers
   - Include example content that triggers the rule

5. **Respond to feedback**
   - Address review comments
   - Update tests or documentation as needed

## What to Contribute

### High-priority contributions
- **New detection rules** for RAG poisoning techniques
- **False positive fixes** - improve precision on legitimate content
- **Performance improvements** - faster scanning for large knowledge bases
- **Research integration** - implement patterns from new RAG security papers

### Medium-priority
- **Format support** - better handling of PDFs, Word docs, etc.
- **CI/CD examples** - GitHub Actions, pre-commit hooks
- **Test cases** - more edge cases, real-world document examples
- **Documentation** - better examples, attack explanations

### Not currently needed
- External dependencies (keep it zero-dependency)
- Rewrites or major refactors (focus on incremental improvements)
- Style-only changes (functional improvements preferred)

## Questions or Ideas?

- **Open an issue** on GitHub for discussion
- **Check existing issues** to avoid duplicates
- **Search closed PRs** - your idea may have been discussed before
- **Read the research** - cite papers like "Knowledge Database or Poison Base?" and OWASP ASI06

## Code of Conduct

Be respectful, inclusive, and constructive. We're all here to build better security tools.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make RAG systems more secure! 🛡️

# Prose Linting Guide

The Clarity-AI Backend project uses Vale, a syntax-aware prose linter, to ensure consistent, accurate, and high-quality documentation. This guide explains how to use Vale for documentation quality control.

## Overview

Vale checks documentation against a defined style to ensure:

- Consistent terminology
- Accurate claims (avoiding unsubstantiated statistics)
- Proper technical language
- HIPAA-compliant terminology
- Active voice (where appropriate)
- Clear, precise language

## Installation

### Installing Vale

```bash
# macOS (using Homebrew)
brew install vale

# Linux (using Snap)
sudo snap install vale

# Other platforms
# See https://vale.sh/docs/vale-cli/installation/
```

### Configuring the Project

The Vale configuration is already set up in the repository:

- `.vale.ini`: Main configuration file
- `.vale/Clarity/`: Custom style rules
- `.vale/Vocab/Clarity/`: Accepted and rejected vocabulary

## Running Vale

Use the provided script to run Vale against documentation:

```bash
# Check all documentation
./scripts/lint_prose.sh

# Check specific files or directories
./scripts/lint_prose.sh docs/content/api/
./scripts/lint_prose.sh docs/content/architecture/overview.md
```

## Understanding Vale Output

Vale produces output in the following format:

```
file.md:12:10:Clarity.UnsubstantiatedClaims:'43% improved' - Potentially unsubstantiated claim...
```

This indicates:
- The file with the issue (`file.md`)
- Line and character position (`12:10`)
- The style rule that triggered (`Clarity.UnsubstantiatedClaims`)
- The problematic text (`'43% improved'`)
- The explanation of the issue

## Vale Rules Explained

### UnsubstantiatedClaims

Flags potentially unsubstantiated statistical claims or exaggerated statements. Replace these with:

- Qualified statements using "aims to," "designed to," etc.
- Statements with proper citations
- More precise descriptions of functionality without claims about effectiveness

### Terminology

Enforces consistent terminology across documentation. For example:

- Use "digital twin" instead of "digital replica" or "virtual model"
- Use "repository" instead of "data access layer" or "DAO"
- Use "entity" instead of "model" or "object"

### HIPAA

Flags HIPAA-related terminology to ensure proper context and safeguards are described when discussing PHI.

### Hedging

Highlights hedging language that may indicate uncertainty, suggesting you consider if a more precise statement is possible.

### PassiveVoice

Suggests replacing passive voice with active voice where appropriate.

## Vocabulary Management

Vale uses accepted and rejected word lists:

- `.vale/Vocab/Clarity/accept.txt`: Approved terminology
- `.vale/Vocab/Clarity/reject.txt`: Discouraged terminology

To add new terms:
1. Add approved terms to `accept.txt`
2. Add discouraged terms to `reject.txt`

## Integration with Text Editors

Vale can be integrated with various text editors:

- VS Code: [Vale VS Code extension](https://marketplace.visualstudio.com/items?itemName=errata-ai.vale-server)
- Sublime Text: [Vale Sublime Text plugin](https://packagecontrol.io/packages/Vale)
- Vim/Neovim: [ALE](https://github.com/dense-analysis/ale) or [Syntastic](https://github.com/vim-syntastic/syntastic)

## CI/CD Integration

Vale is integrated into our CI/CD pipeline to check documentation quality on pull requests. The configuration is in the `.github/workflows/documentation.yml` file.

## Exempting Text

To exempt specific text from Vale checks:

```markdown
<!-- vale off -->
This text will not be checked by Vale.
<!-- vale on -->
```

For inline exemptions:

```markdown
This text is checked, but <!-- vale Clarity.UnsubstantiatedClaims = NO --> this specific term is not <!-- vale Clarity.UnsubstantiatedClaims = YES --> and then checking resumes.
```

## Adding New Rules

To add a new rule:

1. Create a new YAML file in `.vale/Clarity/`
2. Define the rule pattern and message
3. Test the rule against sample documentation

See the [Vale documentation](https://vale.sh/docs/topics/styles/) for detailed information on creating custom rules.
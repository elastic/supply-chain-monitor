# Contributing to Supply Chain Monitor

Thank you for your interest in contributing to Supply Chain Monitor! This document provides guidelines and information for contributors.

## How to Contribute

### Reporting Bugs

Before creating a bug report, please check existing issues to avoid duplicates. When filing a bug, include:

- A clear, descriptive title
- Steps to reproduce the issue
- Expected vs. actual behavior
- Python version and OS
- Relevant log output (from `logs/monitor_YYYYMMDD.log`)

### Suggesting Features

Feature requests are welcome. Please open an issue and describe:

- The problem your feature would solve
- Your proposed solution
- Any alternatives you've considered

### Pull Requests

1. Fork the repository
2. Create a feature branch from `main` (`git checkout -b feature/my-change`)
3. Make your changes
4. Test your changes locally (see [Testing](#testing) below)
5. Commit with a clear message describing the change
6. Push to your fork and open a pull request

#### Pull Request Guidelines

- Keep PRs focused — one logical change per PR
- Update documentation if you change behavior
- Add or update tests where applicable
- Follow the existing code style (see [Code Style](#code-style))

## Development Setup

```bash
# Clone the repo
git clone https://github.com/elastic/supply-chain-monitor.git
cd supply-chain-monitor

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate   # macOS/Linux
.venv\Scripts\activate      # Windows

# Install dependencies
pip install -r requirements.txt

# Install dev dependencies
pip install -r requirements-dev.txt
```

### Prerequisites

- Python 3.9+
- [Cursor Agent CLI](https://cursor.com/docs/cli/overview) (for LLM analysis features)
- A Slack workspace and bot token (optional, for alert testing)

## Testing

```bash
# Run the linter
ruff check .

# Run type checking (on Linux/macOS shells; on PowerShell list files explicitly)
mypy --ignore-missing-imports monitor.py analyze_diff.py package_diff.py pypi_monitor.py slack.py top_pypi_packages.py

# Run a one-shot scan to verify basic functionality
python monitor.py --once --no-npm
```

There is no formal test suite yet — contributions to add one are very welcome!

## Code Style

- Follow [PEP 8](https://peps.python.org/pep-0008/) conventions
- Use type hints where practical
- Keep functions focused and well-documented
- Prefer stdlib over third-party dependencies where reasonable

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

## Questions?

If you have questions or need help, open a GitHub issue or reach out in the [Elastic community Slack](https://ela.st/slack).

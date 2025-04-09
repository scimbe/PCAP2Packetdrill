# Contributing to PCAP2Packetdrill

Thank you for considering contributing to PCAP2Packetdrill! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone. Be kind and constructive in your communications with other contributors.

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue on GitHub with the following information:

1. Clear and descriptive title
2. Steps to reproduce the bug
3. Expected behavior
4. Actual behavior
5. Any relevant logs or screenshots
6. Environment information (OS, Python version, etc.)

### Suggesting Enhancements

For feature requests, please create an issue that includes:

1. Clear and descriptive title
2. Detailed description of the proposed feature
3. Any relevant examples or use cases
4. If applicable, mock-ups or examples of the desired behavior

### Development Process

1. Fork the repository on GitHub
2. Clone your fork locally: `git clone https://github.com/your-username/PCAP2Packetdrill.git`
3. Create a branch for your changes: `git checkout -b feature/your-feature-name`
4. Set up your development environment:
   ```
   cd PCAP2Packetdrill
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e ".[dev]"
   ```
5. Make your changes, following the coding conventions
6. Add tests for your changes
7. Run the tests: `pytest`
8. Update documentation as needed
9. Commit your changes: `git commit -m "Description of your changes"`
10. Push to your fork: `git push origin feature/your-feature-name`
11. Create a pull request from your fork to the main repository

### Pull Request Process

1. Ensure all tests pass and code is well-documented
2. Update the README.md if necessary
3. The pull request will be reviewed by maintainers
4. Address any feedback or requested changes
5. Once approved, your changes will be merged

## Coding Conventions

- Follow [PEP 8](https://peps.python.org/pep-0008/) style guide
- Use meaningful variable and function names
- Write docstrings for all functions, classes, and modules
- Keep functions focused on a single responsibility
- Add comments for complex logic

## Testing

- Write tests for all new features and bug fixes
- Ensure all tests pass before submitting a pull request
- Aim for high test coverage

## Documentation

- Update the documentation for any changes to the API or functionality
- Keep documentation clear, concise, and up-to-date
- Include examples where appropriate

## License

By contributing to this project, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).

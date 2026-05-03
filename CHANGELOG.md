# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-12-17

### Added
- Modern `pyproject.toml` with PEP 621 standard configuration
- Explicit `__all__` exports in package `__init__.py` files
- Ruff configuration for code linting and formatting
- pytest and mypy configuration
- Development dependencies for testing and code quality

### Fixed
- Critical bug in `Tube.recv()` where `self.bufsize` should be `self.buf`
- Removed debug print statements from `tube.py`

### Changed
- Updated Python version requirement to >=3.8 (dropped Python 3.7 and earlier)
- Updated all dependency versions to modern standards
- Improved README with comprehensive examples and documentation
- Better project structure following modern Python packaging standards

## [0.1.0] - Initial Release

### Added
- Initial implementation of roppy toolkit
- Process and remote tube implementations
- ELF binary loader with symbol/PLT/GOT access
- Assembly/disassembly support for x86/x64
- Format string exploitation library
- ROP utilities (SROP frames)
- Packing/unpacking utilities

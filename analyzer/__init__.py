
"""
Binary File Analyzer package for analyzing PE and ELF binary files.

This package provides tools to extract attributes such as imports, exports, section details,
and packer signatures from binary files, with a focus on detecting suspicious characteristics
for malware analysis. It is designed to demonstrate skills in Python programming, binary file
analysis, and cybersecurity, aligning with roles like Cybersecurity Analyst.

Modules:
    pe_analyzer: Analyzes PE (Windows) files for headers, imports, exports, and sections.
    elf_analyzer: Analyzes ELF (Linux) files for headers, symbols, and sections.
    entropy: Calculates Shannon entropy to detect packed or obfuscated sections.
    packer: Detects common packers (e.g., UPX, Themida) based on signatures and entropy.
    report: Generates JSON reports summarizing analysis results.

Usage:
    >>> from analyzer import analyze_pe, analyze_elf
    >>> result = analyze_pe("notepad.exe")
    >>> print(result["imports"])
"""

# Version of the analyzer package
__version__ = "0.1.0"

# Expose key functions for convenient imports
from .pe_analyzer import analyze_pe
from .elf_analyzer import analyze_elf
from .report import generate_report

# Optional: Define package-wide constants
SUPPORTED_FILE_TYPES = ["pe", "elf"]
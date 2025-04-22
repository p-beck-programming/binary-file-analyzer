def detect_packer(pe, sections):
    """
    Detect common packers in a PE file based on section names and entropy.
    
    Args:
        pe (pefile.PE): PE file object.
        sections (list): List of section dictionaries.
    
    Returns:
        str: Detected packer name or "None".
    """
    # Check for common packer section names
    packer_signatures = {
        "UPX": ["UPX0", "UPX1"],
        "Themida": [".themida"],
        "ASPack": [".aspack"]
    }
    for section in sections:
        section_name = section["name"]
        for packer, signatures in packer_signatures.items():
            if any(sig in section_name for sig in signatures):
                return packer
    # Check for high entropy and low import count as packer indicator
    if len(pe.DIRECTORY_ENTRY_IMPORT) < 2 and any(s["entropy"] > 7.0 for s in sections):
        return "Unknown packer (high entropy, low imports)"
    return "None"

def detect_packer_elf(elf, sections):
    """
    Detect common packers in an ELF file based on section names and entropy.
    
    Args:
        elf (ELFFile): ELF file object.
        sections (list): List of section dictionaries.
    
    Returns:
        str: Detected packer name or "None".
    """
    # Check for common ELF packer section names
    packer_signatures = {
        "UPX": [".upx"],
        "mprotect": [".mprotect"]
    }
    for section in sections:
        section_name = section["name"]
        for packer, signatures in packer_signatures.items():
            if any(sig in section_name for sig in signatures):
                return packer
    # Check for high entropy as packer indicator
    if any(s["entropy"] > 7.0 for s in sections):
        return "Unknown packer (high entropy)"
    return "None"

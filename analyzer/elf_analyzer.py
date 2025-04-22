from elftools.elf.elffile import ELFFile
from analyzer.entropy import calculate_entropy
from analyzer.packer import detect_packer_elf

def analyze_elf(file_path):
    """
    Analyze an ELF file and extract attributes (headers, symbols, sections, entropy, packer).
    
    Args:
        file_path (str): Path to the ELF file.
    
    Returns:
        dict: Analysis results including symbols, sections, and packer detection.
    """
    try:
        # Open and parse ELF file
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
    except Exception as e:
        # Handle invalid ELF file
        raise ValueError(f"Invalid ELF file: {str(e)}")
    
    # Initialize result dictionary
    result = {
        "file_type": "ELF",
        "file_path": file_path,
        "headers": {},
        "symbols": [],
        "sections": [],
        "packer": "None",
        "suspicious_flags": []
    }
    
    # Extract header information
    result["headers"] = {
        "machine": elf.header["e_machine"],
        "type": elf.header["e_type"],
        "entry_point": hex(elf.header["e_entry"])
    }
    
    # Extract dynamic symbols (imports/exports)
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym:
        for sym in dynsym.iter_symbols():
            if sym.name:  # Ensure symbol name exists
                result["symbols"].append({
                    "name": sym.name,
                    "type": sym.entry["st_info"]["type"]
                })
    
    # Analyze sections and calculate entropy
    for section in elf.iter_sections():
        section_name = section.name
        section_data = section.data()
        entropy = calculate_entropy(section_data)
        # Flag high entropy as suspicious
        if entropy > 7.0:
            result["suspicious_flags"].append(f"High entropy in section {section_name}: {entropy:.2f}")
        result["sections"].append({
            "name": section_name,
            "size": section.data_size,
            "entropy": entropy
        })
    
    # Detect packer
    result["packer"] = detect_packer_elf(elf, result["sections"])
    
    return result
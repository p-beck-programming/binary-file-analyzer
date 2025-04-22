import pefile
from analyzer.entropy import calculate_entropy
from analyzer.packer import detect_packer

def analyze_pe(file_path):
    """
    Analyze a PE file and extract attributes (headers, imports, exports, sections, entropy, packer).
    
    Args:
        file_path (str): Path to the PE file.
    
    Returns:
        dict: Analysis results including imports, exports, sections, and packer detection.
    """
    try:
        # Initialize PE file object
        pe = pefile.PE(file_path, fast_load=False)
    except pefile.PEFormatError as e:
        # Handle invalid PE file format
        raise ValueError(f"Invalid PE file: {str(e)}")
    
    # Initialize result dictionary
    result = {
        "file_type": "PE",
        "file_path": file_path,
        "headers": {},
        "imports": [],
        "exports": [],
        "sections": [],
        "packer": "None",
        "suspicious_flags": []
    }
    
    # Extract header information
    result["headers"] = {
        "machine": pe.FILE_HEADER.Machine,
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "characteristics": pe.FILE_HEADER.Characteristics
    }
    
    # Extract imports from Import Address Table
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="ignore")
            for imp in entry.imports:
                if imp.name:  # Ensure import name exists
                    result["imports"].append({
                        "dll": dll_name,
                        "function": imp.name.decode("utf-8", errors="ignore")
                    })
    
    # Extract exports from Export Directory
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:  # Ensure export name exists
                result["exports"].append(exp.name.decode("utf-8", errors="ignore"))
    
    # Analyze sections and calculate entropy
    for section in pe.sections:
        section_name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
        entropy = calculate_entropy(section.get_data())
        # Flag high entropy as suspicious
        if entropy > 7.0:
            result["suspicious_flags"].append(f"High entropy in section {section_name}: {entropy:.2f}")
        result["sections"].append({
            "name": section_name,
            "virtual_address": hex(section.VirtualAddress),
            "size": section.SizeOfRawData,
            "entropy": entropy
        })
    
    # Detect packer
    result["packer"] = detect_packer(pe, result["sections"])
    
    # Check for suspicious Windows API calls
    suspicious_apis = ["CreateProcessA", "WriteProcessMemory", "VirtualAlloc"]
    for imp in result["imports"]:
        if imp["function"] in suspicious_apis:
            result["suspicious_flags"].append(f"Suspicious API: {imp['function']}")
    
    return result
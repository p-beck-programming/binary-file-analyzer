import math

def calculate_entropy(data):
    """
    Calculate Shannon entropy of a byte sequence to detect compression or packing.
    
    Args:
        data (bytes): Byte sequence to analyze.
    
    Returns:
        float: Entropy value (0 to 8).
    """
    if not data:
        return 0.0
    # Initialize frequency counter
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    # Calculate entropy
    entropy = 0.0
    length = len(data)
    for count in freq:
        if count > 0:
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
    return entropy
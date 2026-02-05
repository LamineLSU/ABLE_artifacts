rule = [
    b'8B FF 55',     # First pattern: mov edi, edi; push ebp
    b'55',           # Second pattern: push ebp alone
    b'E8 ?? ??? ??', # Third pattern: displacement bytes of the call
]

addresses = ["0x55", "0x55"]  # Addresses to avoid duplicates in different contexts
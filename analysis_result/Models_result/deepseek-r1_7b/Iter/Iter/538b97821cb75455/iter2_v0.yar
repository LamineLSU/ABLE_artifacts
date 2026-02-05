rule "example_rule" : on_insn(
    E8C8FFFF     # Call instruction (3 bytes)
    FF15         # Push dword ptr [ebp+08h] (2 bytes, assuming displacement is known)
    ??:           # Wildcard for unknown operand
    FF15         # Push dword ptr [ebp+08h]
    1C E0        # Part of the next instruction's operand (4 bytes total)
);

on_insn(
    6A            # Conditional jmp near (1 byte)
    ??.??.??.??   # Wildcard for unknown operands
    5A            # Immediate operand (1 byte)
    8B CE E8      # Instruction with operand (3 bytes)
    ??.??.??.???  # Wildcard for unknown operands
    FF           # Push dword ptr [ebp+08h]
    ???          # Wildcard for unknown operand
);

on_insn(
    FF15         # Push dword ptr [ebp+08h] (2 bytes)
    ??.??.??      # Wildcard for unknown operand
    000000        # Immediate operand (6 bytes total, assuming known displacement)
);
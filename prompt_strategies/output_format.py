
COMPREHENSIVE_BYPASS_STRATEGY = """
===============================================================================
BYPASS STRATEGY ANALYSIS
===============================================================================

There are THREE types of bypass targets in a trace. Analyze ALL of them:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STRATEGY A: TARGET THE EVASION CHECK (Most Common - 60% of cases)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Location: Usually in FIRST 30% of trace
Pattern: CALL → TEST → JE/JNE

```
E8 ?? ?? ?? ??        CALL [check_function]   ← Evasion check (VM, debugger, etc.)
85 C0                 TEST EAX, EAX           ← Check return value
0F 84 ?? ?? ?? ??     JE [exit_path]          ← Branch to exit if detected
```

Examples of check functions:
- IsDebuggerPresent, CheckRemoteDebuggerPresent
- GetTickCount (timing checks)
- CPUID-based VM detection
- Registry queries for VM artifacts
- Memory size checks

When to use: When trace shows clear validation logic early on.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STRATEGY B: TARGET THE EXIT DECISION (25% of cases)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Location: Usually in LAST 30% of trace, but BEFORE the exit call
Pattern: Conditional check before exit API

```
85 C0                 TEST EAX, EAX           ← Check flag/result
74 ??                 JE [skip_exit]          ← Could skip the exit
50                    PUSH EAX                ← Push exit code
FF 15 ?? ?? ?? ??     CALL ExitProcess        ← Exit call
```

Exit APIs to look for:
- ExitProcess, TerminateProcess
- NtTerminateProcess, RtlExitUserProcess
- ExitThread (if single-threaded)

When to use: When the check sets a flag and exit is conditional.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STRATEGY C: TARGET THE EVASION STYLE (15% of cases)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Some malware uses specific evasion techniques with unique patterns:

1. **Timing Check** (RDTSC-based):
```
0F 31              RDTSC                    ← Read timestamp
89 C3              MOV EBX, EAX             ← Store first reading
...
0F 31              RDTSC                    ← Second reading
2B C3              SUB EAX, EBX             ← Calculate delta
3D ?? ?? ?? ??     CMP EAX, threshold       ← Compare to threshold
```

2. **CPUID VM Detection**:
```
B8 01 00 00 00     MOV EAX, 1
0F A2              CPUID                    ← Get CPU info
F7 C1 ?? ?? ?? ??  TEST ECX, hypervisor_bit ← Check hypervisor
```

3. **Sleep Acceleration Check**:
```
FF 15 ?? ?? ?? ??  CALL GetTickCount        ← Get time before
FF 15 ?? ?? ?? ??  CALL Sleep               ← Sleep for X ms
FF 15 ?? ?? ?? ??  CALL GetTickCount        ← Get time after
2B ??              SUB [compare times]      ← Check if accelerated
```

When to use: When trace shows specific anti-analysis technique.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DECISION PROCESS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. First, identify the EXIT POINT (marked with >>> in trace)
2. Then, trace BACKWARDS to find what CAUSED the exit decision
3. Look for CALL+TEST+JE patterns at different locations
4. Choose the EARLIEST viable bypass point (usually gives best results)
5. If early check not found, consider targeting the exit decision itself

**Priority Order:**
1. Evasion check in first 30% → highest success rate
2. Exit decision with conditional jump → moderate success
3. Exit call itself → usually fails (program already decided to exit)
"""

ANTI_GENERIC_MINIMAL = """
===============================================================================
PATTERN QUALITY REQUIREMENTS
===============================================================================

Your pattern MUST be specific enough to uniquely identify the bypass location.

**RULES:**
1. Minimum 8-10 bytes in pattern
2. Include 2-3 consecutive instructions for context
3. Use ?? wildcards ONLY for addresses/offsets that vary between samples
4. Keep opcode bytes fixed (they identify instruction types)

**AVOID:** Single-instruction patterns, patterns < 8 bytes, mostly-wildcard patterns.
"""

ANTI_GENERIC_PATTERNS_SECTION = """
===============================================================================
CRITICAL: AVOID GENERIC PATTERNS
===============================================================================

DO NOT generate patterns that are too generic and will match everywhere:

BAD PATTERNS (will match thousands of locations):
- { FF 15 ?? ?? ?? ?? }           -- matches ANY indirect call
- { E8 ?? ?? ?? ?? }              -- matches ANY relative call
- { 85 C0 }                       -- matches ANY "test eax, eax"
- { 74 ?? } or { 75 ?? }          -- matches ANY short jump
- { 0F 84 ?? ?? ?? ?? }           -- matches ANY je/jz

GOOD PATTERNS (specific enough to be unique):
- { 85 C0 74 07 50 FF 15 ?? ?? ?? ?? }  -- test+je+push+call sequence
- { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }  -- call+test+je sequence
- { 53 FF 15 ?? ?? ?? ?? 85 C0 }  -- push ebx + call + test pattern

RULES FOR GOOD PATTERNS:
1. Include 2-3 instructions BEFORE the target instruction for context
2. Pattern should be at least 8-10 bytes long
3. Include enough fixed bytes (not ??) to make it unique
4. Look for the EVASION CHECK pattern, not just ExitProcess call
"""

STANDARD_OUTPUT_FORMAT = """
===============================================================================
REQUIRED OUTPUT FORMAT (MUST FOLLOW EXACTLY)
===============================================================================

You MUST provide the following fields in EXACTLY this format:

**PATTERN_TYPE**: [CALL_TEST_JE | API_CHECK | CMP_SETZ | VM_DETECT | DEBUG_CHECK | TIMING_CHECK | OTHER]

**LOCATION**: Line [line_number] ([percentage]% through trace)

**OPCODES_SPECIFIC**: [exact hex bytes from trace, e.g., E8 25 05 00 00 85 C0 0F 84 8A 00 00 00]

**OPCODES_GENERIC**: [hex bytes with wildcards, e.g., E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ??]

**SKIP_OFFSET**: +[offset, usually 0]

**CONFIDENCE**: [0-100]

**REASONING**: [1-2 sentences explaining why this pattern was selected]

**YARA_RULE**:
```yara
rule Bypass_Sample
{{
    meta:
        description = "[pattern_type] evasion bypass"
        pattern_type = "[PATTERN_TYPE value]"
        confidence = "[CONFIDENCE value]"
        location = "[LOCATION value]"
        cape_options = "bp0=$pattern+[SKIP_OFFSET],action0=skip,count=0"

    strings:
        $pattern = {{ [OPCODES_GENERIC value] }}

    condition:
        $pattern
}}
```

IMPORTANT:
- Use OPCODES_GENERIC (with wildcards) in the YARA rule for better matching
- Replace all addresses with ?? wildcards (e.g., E8 ?? ?? ?? ??)
- Keep opcode bytes (85 C0, 0F 84, 74, 75) as-is
- Confidence should reflect pattern match quality (90+ = high, 70-89 = medium, <70 = low)
"""

PATTERN_TYPES = {
    "CALL_TEST_JE": "Function call followed by TEST eax,eax and conditional jump",
    "API_CHECK": "Direct API call for environment detection (IsDebuggerPresent, etc.)",
    "CMP_SETZ": "Comparison with SETZ/SETNE conditional set",
    "VM_DETECT": "Virtual machine detection (CPUID, registry checks)",
    "DEBUG_CHECK": "Debugger detection (PEB, timing, etc.)",
    "TIMING_CHECK": "Timing-based evasion (GetTickCount, RDTSC)",
    "OTHER": "Pattern doesn't fit standard categories"
}

CONFIDENCE_GUIDE = """
Confidence Scoring Guide:
- 95-100: Perfect pattern match, early in trace, known evasion technique
- 85-94: Strong match, clear bypass point, high certainty
- 70-84: Good match, some uncertainty about exact offset
- 50-69: Reasonable guess, pattern present but unclear
- 0-49: Low confidence, speculative bypass
"""


def get_standard_output_section() -> str:

    return STANDARD_OUTPUT_FORMAT


def validate_output_fields(response: str) -> dict:

    import re

    required_fields = [
        "PATTERN_TYPE",
        "LOCATION",
        "OPCODES_SPECIFIC",
        "OPCODES_GENERIC",
        "SKIP_OFFSET",
        "CONFIDENCE",
        "REASONING"
    ]

    missing = []
    for field in required_fields:
        patterns = [
            rf'\*\*{field}\*\*:',
            rf'{field}:',
        ]
        found = any(re.search(p, response, re.IGNORECASE) for p in patterns)
        if not found:
            missing.append(field)

    if not re.search(r'```yara.*rule\s+\w+.*```', response, re.DOTALL | re.IGNORECASE):
        missing.append("YARA_RULE")

    return {
        'valid': len(missing) == 0,
        'missing_fields': missing,
        'fields_found': len(required_fields) - len(missing) + (0 if "YARA_RULE" in missing else 1),
        'total_fields': len(required_fields) + 1
    }

# YARA Rule Correction Required

Your previous YARA rule generation attempt failed validation. Please analyze the errors below and generate a CORRECTED rule.

---

## VALIDATION ERRORS

{{errors}}

---

## YOUR PREVIOUS (INVALID) RULE

```yara
{{previous_rule}}
```

---

## ERROR ANALYSIS

{{error_analysis}}

---

## ORIGINAL TASK (for reference)

{{original_prompt}}

---

## CORRECTION GUIDE

Based on the validation errors above, generate a NEW corrected YARA rule.

### CRITICAL REQUIREMENTS (MUST FOLLOW)

1. **EXACTLY 3 PATTERNS**: You MUST have `$pattern0`, `$pattern1`, `$pattern2` - no more, no less
2. **CAPE_OPTIONS REQUIRED**: You MUST include cape_options in meta section for bypass to work
3. **6-20 BYTES PER PATTERN**: Each pattern must be 6-20 bytes
4. **WILDCARDS REQUIRED**: Replace address/offset bytes with `??` wildcards

### Common Errors and How to Fix Them

| Error Type | Problem | Solution |
|------------|---------|----------|
| **"too short"** | Pattern has < 6 bytes | Combine 2-3 consecutive instructions into one pattern. Include target + context. |
| **"address bytes" / "hardcoded"** | Raw addresses in pattern | Replace ALL address/offset bytes with `??`. CALL offsets = 4 bytes after opcode. |
| **"duplicate patterns"** | Two patterns are identical | Select DIFFERENT instruction sequences from the trace. |
| **"cape_options missing"** | No bypass metadata | Add to meta: `cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"` |
| **"syntax error"** | Invalid YARA format | Check: braces `{ }` around hex, spaces between bytes, pattern names start with `$` |
| **"not 3 patterns"** | Wrong pattern count | Must have exactly `$pattern0`, `$pattern1`, `$pattern2` |

### Byte-Level Fix Examples

**CALL instruction (E8 + 4 offset bytes):**
- Wrong: `E8 25 05 00 00` (hardcoded offset)
- Right: `E8 ?? ?? ?? ??`

**Conditional JMP short (74/75 + 1 offset byte):**
- Wrong: `74 1A` or `75 0C`
- Right: `74 ??` or `75 ??`

**Conditional JMP near (0F 84/0F 85 + 4 offset bytes):**
- Wrong: `0F 84 8A 00 00 00`
- Right: `0F 84 ?? ?? ?? ??`

**Memory access with displacement:**
- Wrong: `8B 45 FC` (stack offset FC)
- Right: `8B 45 ??`

---

### CORRECT FORMAT TEMPLATE

```yara
rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}
```

---

Generate ONLY the corrected YARA rule following the template above. You MUST have exactly 3 patterns with cape_options.

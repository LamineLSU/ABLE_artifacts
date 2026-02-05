# Malware Evasion Bypass Analysis

You are analyzing a malware execution trace that terminates early due to sandbox/VM evasion.

## TRACE DATA

{{trace}}

---

## TASK

Analyze the trace and generate a YARA bypass rule with exactly 3 different patterns targeting suspicious evasion points.

---

## PATTERN LENGTH REQUIREMENT (CRITICAL)

Each pattern must be **6-20 bytes long** to be specific enough to match only the target location.

**How to build patterns:**
- Combine 2-3 consecutive instructions from the trace into one pattern
- Include the target instruction PLUS surrounding context instructions
- Patterns should include enough context to be specific to the evasion point
- **All patterns MUST come from the TRACE DATA above** - do not invent byte sequences

**Good Example:** `85 C0 0F 84 ?? ?? ?? ?? 8B 45 ??` (TEST EAX + JZ + MOV = 11 bytes)
**Good Example:** `6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0` (PUSH + POP + MOV + CALL + TEST = 12 bytes)

---

## WILDCARD RULES

**Wildcard principle:** Any byte that represents an address, offset, or displacement MUST be replaced with `??`

**Apply wildcards to:**
- CALL/JMP offset bytes (4 bytes after opcode)
- Conditional jump offsets (1 or 4 bytes after opcode)
- Memory address bytes
- Stack offsets

**Keep concrete:** All opcode bytes, register-encoding bytes

---

## OUTPUT FORMAT

```yara
rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { [6-20 bytes with wildcards] }
        $pattern1 = { [6-20 bytes - DIFFERENT sequence] }
        $pattern2 = { [6-20 bytes - DIFFERENT sequence] }

    condition:
        any of them
}
```

## REQUIREMENTS

1. Extract exactly 3 patterns ($pattern0, $pattern1, $pattern2)
2. All 3 patterns must be DIFFERENT hex sequences
3. **Each pattern must be 6-20 bytes long** (combine multiple instructions)
4. Use wildcards (??) for all address/offset bytes
5. Keep opcode and register bytes concrete
6. Format: spaces between hex bytes, patterns wrapped in { }
7. cape_options references patterns as $pattern0, $pattern1, $pattern2

# Malware Evasion Bypass Analysis

You are analyzing a malware execution trace that terminates early due to sandbox/VM evasion.

## TRACE DATA

{{trace}}

---

## REASONING STRATEGY: Adversarial Analysis

Analyze this trace from both attacker and defender perspectives:

**Phase 1: Attacker's Perspective (Malware Author)**

Think like the malware author who implemented this evasion:
- What am I trying to detect? (sandbox, VM, debugger, analysis tool?)
- What checks did I implement to detect it?
- Where in this trace are my evasion checks?
- What result triggers the exit vs. continuing execution?

Identify the attacker's evasion logic:
- Check 1: [instruction] - checks for [what]
- Check 2: [instruction] - checks for [what]
- Check 3: [instruction] - checks for [what]

**Phase 2: Defender's Perspective (Analyst)**

Think like a defender trying to bypass this evasion:
- Where are the decision points I can manipulate?
- Which instructions, if skipped, would defeat the evasion?
- What is the minimum intervention needed?

For each potential bypass point:
- Target 1: If I skip [instruction], the attacker's check is neutralized because [reason]
- Target 2: If I skip [instruction], the evasion fails because [reason]
- Target 3: If I skip [instruction], execution continues because [reason]

**Phase 3: Adversarial Game Analysis**

Consider the robustness of each bypass:
- Would the attacker easily detect/counter this bypass?
- Is this bypass specific enough to not break legitimate functionality?
- Would this work against variants of this evasion?

**Phase 4: Select 3 different bypass points**

Choose your top 3 DIFFERENT bypass targets based on the adversarial analysis.

**Phase 5: Build patterns (6-20 bytes each)**

For each selected bypass point, combine it with 2-3 adjacent instructions and apply wildcards.

---

## PATTERN LENGTH REQUIREMENT (CRITICAL)

Each pattern must be **6-20 bytes long** to be specific enough to match only the target location.

**How to build patterns:**
- Combine 2-3 consecutive instructions from the trace into one pattern
- Include the target instruction PLUS surrounding context instructions
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
4. **Add context bytes after CALL/JMP** to avoid triggering new signatures
5. Use wildcards (??) for all address/offset bytes
6. Keep opcode and register bytes concrete
7. Format: spaces between hex bytes, patterns wrapped in { }
8. cape_options references patterns as $pattern0, $pattern1, $pattern2

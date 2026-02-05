# Malware Evasion Bypass Analysis

You are analyzing a malware execution trace that terminates early due to sandbox/VM evasion.

## TRACE DATA

{{trace}}

---

## REASONING STRATEGY: Counterfactual Analysis

Analyze this trace using counterfactual reasoning ("what if" scenarios):

**Phase 1: Establish the factual outcome**
- The program exits (this is the observed fact)
- Identify the exact instruction sequence leading to exit

**Phase 2: Generate counterfactual hypotheses**
For each suspicious instruction, ask:
- "What if this instruction were skipped?"
- "Would the program continue instead of exiting?"

**Phase 3: Evaluate each hypothesis**
For each candidate instruction:

*Counterfactual 1:* [Instruction at line X]
- Factual: This instruction executes → leads to exit
- Counterfactual: If skipped → would execution continue?
- Necessity: Is skipping this NECESSARY to prevent exit?
- Sufficiency: Is skipping this SUFFICIENT to prevent exit?

*Counterfactual 2:* [Different instruction at line Y]
- Same analysis...

*Counterfactual 3:* [Another instruction at line Z]
- Same analysis...

**Phase 4: Select the 3 best bypass points**
Choose instructions where skipping is likely SUFFICIENT to bypass evasion.

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

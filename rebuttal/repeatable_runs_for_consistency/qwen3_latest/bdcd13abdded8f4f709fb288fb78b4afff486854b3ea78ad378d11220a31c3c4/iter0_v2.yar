rule bypass_patterns
{
    meta:
        description = "Patterns to bypass evasion by targeting specific CALL/RET sequences"
        cape_options = "bp0=$call1+0,action0=skip,bp1=$call2+0,action1=skip,bp2=$ret+0,action2=skip,count=0"
        author = "Security Researcher"
        date = "2023-10-15"

    strings:
        // Pattern 0: CALL sequence with PUSH/LEA context
        $call1 = { 6A 36 6A 00 51 8D B0 ?? ?? ?? ?? 56 50 E8 ?? ?? ?? ?? }

        // Pattern 1: Another CALL sequence with different LEA context
        $call2 = { 51 8D B0 ?? ?? ?? ?? 56 50 E8 ?? ?? ?? ?? 8B 55 0C }

        // Pattern 2: RET instruction after ADD ESP
        $ret = { 8B 06 83 C4 14 C3 }

    condition:
        all of ($call1 or $call2 or $ret)
}
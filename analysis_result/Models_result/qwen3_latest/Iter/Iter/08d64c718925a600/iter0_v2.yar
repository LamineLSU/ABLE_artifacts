rule ExitPattern
{
    meta:
        description = "Detects code flow leading to an exit point"
        cape_options = "bp0=$call1+0,action0=skip,bp1=$jump1+0,action1=skip,bp2=$call2+0,action2=skip,count=0"
    strings:
        // Pattern 1: Call followed by PUSH and TEST
        $call1 = { E8 ?? ?? ?? ?? 6A 00 85 C0 }

        // Pattern 2: Conditional jump followed by MOV and CALL
        $jump1 = { 74 ?? 8B 45 ?? E8 ?? ?? ?? ?? }

        // Pattern 3: PUSH, POP, and CALL sequence
        $call2 = { 6A ?? 5A E8 ?? ?? ?? ?? }
    condition:
        any of them
}
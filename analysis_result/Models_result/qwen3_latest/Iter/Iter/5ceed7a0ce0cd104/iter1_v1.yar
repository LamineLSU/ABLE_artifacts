rule Bypass_Sample
{
    meta:
        description = "Detects potential evasion or obfuscation patterns in memory"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 F8 01 74 ?? }  // Call, compare, conditional jump
        $pattern1 = { A8 01 74 ?? FF 75 08 }             // Test, jump, push (evasion sequence)
        $pattern2 = { FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? }  // Call, push, call (function calls)

    condition:
        any of them
}
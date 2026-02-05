rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 75 ?? ?? ?? ?? 8B 44 24 04 }  // JNE + preceding instruction
        $pattern1 = { 7F ?? ?? ?? ?? 8B 44 24 04 }  // JNP + preceding instruction
        $pattern2 = { E8 ?? ?? ?? ?? C3 }           // CALL + RET

    condition:
        any of them
}
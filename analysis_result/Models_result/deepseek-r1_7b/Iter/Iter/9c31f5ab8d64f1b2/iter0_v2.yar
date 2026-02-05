rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? 74 00 00 }  // Bypasses a conditional jump
        $pattern1 = { E8 ?? ?? ?? ?? 8B FC }  // Skips a near call with displacement
        $pattern2 = { E8 ?? ?? ?? ?? 6A ?? }  // Bypasses another conditional jump

    condition:
        any of them
}
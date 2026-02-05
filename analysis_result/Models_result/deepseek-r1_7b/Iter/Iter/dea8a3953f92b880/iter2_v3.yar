rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns targeting different instruction sequences"
        cape_options = "bp0=E8250500+0,action0=skip,bp1=741A+0,action1=skip,bp2=6A3B+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 25 05 00 ?? ?? ?? ?? }  // Call instruction with wildcarded offset
        $pattern1 = { 74 1A ?? ?? ?? ?? ?? }  // Conditional jump with unknown offset
        $pattern2 = { 6A 3B ?? ?? ?? }       // Move instruction with wildcards

    condition:
        any of them
}
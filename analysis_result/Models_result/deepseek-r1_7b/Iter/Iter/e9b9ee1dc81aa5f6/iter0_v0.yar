rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns targeting stack overflow checks in different execution paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 E8 C0 57 E8 C0 }
        $pattern1 = { 6A 00 5A 8B CE E8 5E FF ?? ?? }
        $pattern2 = { F8 3C 24 00 ?? ?? ?? 8D C8 7F 50 ?? ?? 8D D9 15 60 ?? ?? ?? ?? ?? 00 00 00 00 }

    condition:
        any of them
}
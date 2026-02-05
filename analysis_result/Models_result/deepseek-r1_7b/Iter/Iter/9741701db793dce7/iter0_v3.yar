rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 E8 B7 F7 FF FF ?? ?? ?? ?? 42 0B E0 }
        $pattern1 = { 85 C0 E8 E0 A2 FF FF FF ?? ?? ?? ?? 41 0B 70 }
        $pattern2 = { 85 C0 E8 F7 F4 00 ?? ?? ?? ?? 32 14 }

    condition:
        any of them
}
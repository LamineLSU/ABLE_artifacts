rule Bypass_Sample {
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { ?? ?? ?? FF 75 08 }
        $pattern2 = { E8 0D 0C 00 00 ?? FF 15 AC B0 41 00 ?? }

    condition:
        any of them
}
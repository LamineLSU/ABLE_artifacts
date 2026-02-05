rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 F8 04 92 03 A7 50 13 C0 }
        $pattern1 = { E8 C8 FF FF FF 75 08 FF 15 AC B0 41 00 13 D0 }
        $pattern2 = { E8 C8 FF FF FF 75 08 FF 75 08 13 F0 }

    condition:
        any of them
}
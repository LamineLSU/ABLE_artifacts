rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? FF 15 D8 54 41 00 FF 75 08 6A 00 FF 75 FC }
        $pattern1 = { 50 FF 15 D8 54 41 00 FF 75 08 FF 15 9C 54 41 00 6A 00 6A 09 5F C8 }
        $pattern2 = { 50 E8 ?? ?? ?? ?? FF 15 D8 54 41 00 FF 75 08 FF 15 9C 54 41 00 6A 00 6A 09 5F C8 }

    condition:
        any of them
}
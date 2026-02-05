rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { C7 06 00 00 00 00 83 C6 04 4B 75 F4 33 C0 }
        $pattern1 = { 8D B5 A4 FC FF FF BB C8 00 00 00 C7 06 00 00 00 00 83 C6 04 }
        $pattern2 = { E8 8E 07 00 00 E8 D1 0E 00 00 68 01 00 00 80 }

    condition:
        any of them
}
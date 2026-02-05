rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 00 D0 61 F8 E9 B5 FC FF FF 33 DB BA 21 05 00 }
        $pattern1 = { 85 C0 00 A7 61 F8 E9 B5 FC FF FF 33 DB BA 21 05 00 }
        $pattern2 = { 85 C0 01 38 61 F8 E9 B5 FC FF FF 33 DB BA 21 05 00 }

    condition:
        any of them
}
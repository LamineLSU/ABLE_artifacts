rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 E0 61 CB E8 E3 FA FF FF 50 00 }
        $pattern1 = { 01 46 16 F8 FF 15 2C A1 14 00 53 }
        $pattern2 = { 00 96 19 F8 FF 15 2C A1 10 90 53 }

    condition:
        any of them
}
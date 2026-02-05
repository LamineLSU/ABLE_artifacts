rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns targeting suspicious points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { FF 75 08 E8 C8 FF 15 AC B0 41 00 }
        $pattern1 = { FF 75 08 FF 15 AC B0 41 00 }
        $pattern2 = { 8D 47 B5 00 00 01 10 2C 16 E2 0F 00 }

    condition:
        any of them
}
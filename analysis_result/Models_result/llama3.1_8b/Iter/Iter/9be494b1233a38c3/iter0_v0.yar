rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 56 57 6A 04 68 00 30 00 BE 70 5D 1E 00 }
        $pattern1 = { 50 FF D6 E8 63 FB 00 8A 08 3A 0E }
        $pattern2 = { FF 15 F8 8F 6E 00 57 8D 85 C0 FB FF 53 }

    condition:
        any of them
}
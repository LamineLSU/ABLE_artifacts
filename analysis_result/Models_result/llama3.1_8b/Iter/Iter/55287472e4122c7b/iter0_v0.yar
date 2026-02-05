rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 FF 15 FC 64 45 00 }
        $pattern1 = { 8B C0 FC 85 C9 0B C0 F8 }
        $pattern2 = { 6A 00 68 C0 9E E6 05 6A 00 FF 75 FC }

    condition:
        any of them
}
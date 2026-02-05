rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 5E 5D C3 52 8B 16 50 51 FF D2 }
        $pattern1 = { 79 B4 1E 7C C0 00 41 E2 9F }
        $pattern2 = { 56 6A 35 51 8B 48 14 56 6A 00 51 8D B0 90 C0 }

    condition:
        any of them
}
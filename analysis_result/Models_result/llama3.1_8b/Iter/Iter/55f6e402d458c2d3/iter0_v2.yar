rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B ?? FC 42 ?? C7 DC ?? 83 EC ?? }
        $pattern1 = { 6A ?? 57 8D 85 B4 FD FF FF BE 88 46 10 50 56 }
        $pattern2 = { 68 D0 07 00 00 00 00 E8 E9 DB FF FF FF FF C7 }

    condition:
        any of them
}
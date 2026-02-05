rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { 68 C0 41 C8 17 6A 00 FF 15 08 60 44 00 8B F0 50 83 F8 11 74 05 }
        $pattern2 = { FF 15 20 95 45 00 8D 95 94 FE FF FF 8D 8D EC FE FF FF 52 C7 85 94 FE FF FF 3C 00 00 00 }
        $pattern3 = { A1 64 66 45 00 33 C4 89 44 24 44 6A 40 }

    condition:
        any of them
}
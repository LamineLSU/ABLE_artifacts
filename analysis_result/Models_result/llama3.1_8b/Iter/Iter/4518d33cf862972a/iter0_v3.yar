rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 8B D0 E8 7D AE 00 00 75 1D E8 0B B3 00 00 8B 0D 60 72 EA 00 }
        $pattern1 = { 53 56 57 33 DB 53 6A 40 BE 30 00 00 E8 D0 07 00 }
        $pattern2 = { 50 FF 15 E7 74 EA 00 6A 3C 8D 85 EC FE FF FF 5B }

    condition:
        any of them
}
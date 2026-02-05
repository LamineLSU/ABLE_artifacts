rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { E8 54 00 00 00 50 ?? ?? ?? 8B EC 81 C4 00 FC FF FF }
        $pattern2 = { 6A 02 FF B5 A4 FC FF FF ?? ?? FF B5 A4 FC FF FF E8 42 08 00 00 }
        $pattern3 = { E8 87 07 00 00 B9 C8 00 00 00 ?? 75 EF FF B5 80 F9 FF FF }

    condition:
        any of them
}
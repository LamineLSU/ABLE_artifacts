rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 45 33 C9 89 74 24 28 45 33 C0 BA 00 00 00 C0 C7 44 24 20 02 00 00 00 FF 15 F1 0E 00 00 48 8B F8 }
        $pattern1 = { 48 89 74 24 30 00 00 7F F7 2B A5 10 F0 00 00 7F F7 2B A5 10 FA 00 00 7F F7 2B A5 10 FD C7 44 24 20 02 00 00 00 FF 15 B2 0E 00 00 }
        $pattern2 = { 48 8B CF 00 00 7F F7 2B A5 11 5A 48 8D 54 24 40 FF 15 CB 0E 00 00 FF 15 AA 0E 00 00 }

    condition:
        any of them
}
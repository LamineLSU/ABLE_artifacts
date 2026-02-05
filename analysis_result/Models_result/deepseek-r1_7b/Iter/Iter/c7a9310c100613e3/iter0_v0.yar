rule Bypass_Evasion {
    meta:
        description = "Evasion bypass patterns targeting memory/stack checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 66 83 F8 01 50 50 FF 15 80 51 A1 03 FF 1D }
        $pattern1 = { 6A 37 5A E8 2A 7E 00 00 6A 27 5A 66 83 F8 01 75 20 FF 15 80 51 A1 03 50 FF 15 C4 50 A1 03 }
        $pattern2 = { 6A 00 FF 15 38 51 A1 03 E8 2A 7E 00 00 6A 00 FF 15 13 C3 }

    condition:
        any of them
}
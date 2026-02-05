rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection patterns targeting call evasions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 43 1C 00 00 E8 E0 A2 FF FF 85 C0 74 0E E8 B7 F7 FF FF 6A 00 }
        $pattern1 = { E8 B7 F7 FF FF 85 C0 E8 E0 A2 FF FF 6A 00 5A E8 89 E0 FF FF }
        $pattern2 = { 6A 00 85 C0 5A E8 E0 A2 FF FF CE E8 B7 F7 FF FF }

    condition:
        any of them
}
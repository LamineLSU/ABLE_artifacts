rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF F9 84 3F 75 0D 6A 40 5B 04 01 B0 04 FF 0F 0F 00 00 00 }
        $pattern1 = { 85 C0 E8 25 F0 74 12 3C 6A 40 5B 04 01 B0 04 FF 88 88 08 50 20 5E }
        $pattern2 = { 85 C0 74 12 3C E8 25 F0 6A 40 5B 04 01 B0 04 FF 9B 5D FC FF FF FF FF }

    condition:
        any of them
}
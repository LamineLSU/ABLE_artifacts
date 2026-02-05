rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5A E8 54 D3 FF FF 8D 85 4C F2 FF FF 50 A1 AC 5B 35 02 E8 E7 E9 FF FF 8B D0 8D 85 48 F2 FF FF 5A }
        $pattern1 = { 5A E8 54 D3 FF FF 8D 85 4C F2 FF FF 50 A1 AC 5B 35 02 E8 E7 E9 FF FF 8B D0 8D 85 48 F2 FF FF 5A BA D8 F6 34 02 E8 72 E5 FF FF 8B 85 44 F2 FF FF 5A 50 E8 E7 E9 FF FF 8B D0 8D 85 40 F2 FF FF }
        $pattern2 = { 5A E8 54 D3 FF FF BA D8 F6 34 02 E8 72 E5 FF FF 8B 85 44 F2 FF FF 5A 50 E8 E7 E9 FF FF 8B D0 8D 85 40 F2 FF FF 5A 50 E8 E8 FE FF FF BA D8 F6 34 00 E8 B5 96 FF FF }

    condition:
        any of them
}
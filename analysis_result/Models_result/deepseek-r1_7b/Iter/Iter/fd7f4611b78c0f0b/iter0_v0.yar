rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection for memory encryption"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 FF 75 08 E8 C8 ?? F0 5A FF FB FF FE FF }
        $pattern1 = { 6A 5A FF 75 08 FF 15 AC B0 41 00 }
        $pattern2 = { 50 8D 95 F0 FE FF FF FF D9 53 E8 45 ?? 8B EC }

    condition:
        any_of($pattern0, $pattern1, $pattern2)
}
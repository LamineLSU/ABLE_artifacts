rule EvasionBypass_Patterns {
    meta:
        description: "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 74 FF 75 08 E8 C8 FF FF FF }
        $pattern1 = { 8B 74 FF 75 08 E8 74 FA FF FF }
        $pattern2 = { 8B 74 FF 75 08 E8 C8 FF FF FF E8 0D 0C 00 00 }

    condition:
        any of them
}
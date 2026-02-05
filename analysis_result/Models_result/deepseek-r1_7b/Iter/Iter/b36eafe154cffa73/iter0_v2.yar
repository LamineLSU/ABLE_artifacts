rule Bypass_Evasion_001 {
    meta:
        description = "Evasion bypass detection using counterfactual analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 08 ?? ?? ?? ?? FF 15 88 7C 42 00 }
        $pattern1 = { E8 4B FF FF FF FF 15 5C 7D 42 00 ?? ?? ?? ?? FF 15 88 7C 42 00 }
        $pattern2 = { 6A 00 00 00 ?? ?? ?? ?? FF 15 C0 7C 42 00 }

    condition:
        any of them
}
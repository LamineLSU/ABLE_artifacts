rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection based on modified instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 02 43 9D 0E FE D7 00 FF 8F 8C FF 00 8C F7 FA CB 00 11 }
}

condition:
    (any of them)
}
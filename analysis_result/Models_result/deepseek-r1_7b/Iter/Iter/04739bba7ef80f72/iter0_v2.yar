rule Bypass_Sample {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 45 6A ?? ?? ?? ?? 5A ?? E8 B7 F7 FF FF }
        $pattern1 = { E8 43 1C 00 00 ?? ?? ?? 74 0E ?? FF 15 14 28 43 00 }
        $pattern2 = { E8 EE 82 FF FF 74 0E ?? ?? 6A ?? 8B EC FF FF }

    condition:
        any of them
}
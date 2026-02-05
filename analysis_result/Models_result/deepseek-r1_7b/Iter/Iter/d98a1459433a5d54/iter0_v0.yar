rule Bypass_Evasion_V1 {
    meta:
        description = "Evasion bypass sequences targeting specific address calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B C0 5A ?? E8 ?? ?? ?? ?? FF 15 2C A1 84 00 } // Push ESI and call target
        $pattern1 = { 6A 5B 8B CE E8 ?? ?? ?? ?? 85 C0 00 00 FF 15 2C 12 40 00 } // Push, pop, call target
        $pattern2 = { 8B C0 5A 8B 45 E8 ?? ?? ?? ?? 8D 95 F0 FE F8 ?? 8B EC 00 FF 15 2C 36 00 } // Extended sequence with stack manipulation
    condition:
        any of them
}
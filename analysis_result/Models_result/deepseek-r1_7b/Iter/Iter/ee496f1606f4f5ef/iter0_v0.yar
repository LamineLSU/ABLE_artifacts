rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }  // Example pattern capturing XOR and pop leading to a call
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }  // Another pattern with push/pop operations before a call
        $pattern2 = { 00 0F 45 7E ?? ?? 7E 7E ?? ?? FE ?? FE 7E ?? ?? FE }  // A third unique sequence involving LEA and call instructions
    condition:
        any of them
}
rule Bypass_Sample {
    meta:
        description = "Evasion bypass using conditional jumps and function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B ?? ?? ?? ?? ?? 83 C4 ?? 85 C0 33 C0 }
        $pattern1 = { E8 ?? ?? ?? ?? 6E 83 C0 75 20 ?? ?? ?? ?? 66 83 F8 01 ?? }
        $pattern2 = { FF 15 34 51 A1 03 ?? ?? ?? ?? 8B 45 ?? ?? ?? ?? }

    condition:
        any of them
}
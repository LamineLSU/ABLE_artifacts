rule Bypass_Sample {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 F7 64 A1 30 8B 45 ?? } // Around the first JE and push ebp
        $pattern1 = { 75 10 1A ?? ?? } // Around the second bypass attempt
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? } // Around another bypass check

    condition:
        any of them
}
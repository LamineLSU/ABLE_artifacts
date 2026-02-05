rule Bypass_Sample {
    meta:
        description = "Evasion bypass of conditional jump instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 42 11 D0 }
        $pattern1 = { 0F 84 8A ?? ?? ?? ?? E8 ?? ?? ?? ?? 5B 84 33 FD }
        $pattern2 = { 8B CE 8B ?? ?? ?? ?? E8 ?? ?? ?? ?? 8C 41 14 00 }

    condition:
        any of them
}
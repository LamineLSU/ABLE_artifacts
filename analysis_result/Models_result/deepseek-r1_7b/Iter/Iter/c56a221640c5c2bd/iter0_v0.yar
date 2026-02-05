rule Bypass_Sample {
    meta:
        description = "Evasion bypass detection using specific instruction patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 FB EC F1 4C CC FC ?? }
        $pattern1 = { 6A ?? 5A 8B CE ?? ?? ?? ?? }
        $pattern2 = { 7E ?? ?? ?? F0 00 00 }

    condition:
        any_of_them
}
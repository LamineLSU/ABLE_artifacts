rule Bypass_Sample {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 F8 5C 05 00 00 74 1A }
        $pattern1 = { 6A 5C 8B CE E8 75 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 53 8B EC 8D FF F8 50 00 00 00 85 C0 }

    condition:
        any of them
}
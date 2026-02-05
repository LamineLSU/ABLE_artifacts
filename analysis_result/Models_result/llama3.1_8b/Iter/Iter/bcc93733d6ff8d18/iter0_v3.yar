rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5B 8B CE E8 ?? ?? ?? ?? }
        $pattern1 = { 33 DB BA 21 05 00 53 6A 40 }
        $pattern2 = { 68 ?? ?? ?? FC 00 E8 ?? ?? }

    condition:
        any of them
}
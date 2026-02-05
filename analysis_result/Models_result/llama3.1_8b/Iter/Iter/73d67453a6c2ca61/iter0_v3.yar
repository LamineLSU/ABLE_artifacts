rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { 74 ?? ?? ?? ?? ?? }
        $pattern2 = { 8B CE E8 ?? ?? ?? ?? }
        $pattern3 = { B8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}
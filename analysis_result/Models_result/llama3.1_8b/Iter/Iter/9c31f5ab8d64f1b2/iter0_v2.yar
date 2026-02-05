rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern3 = { 64 A1 ?? ?? ?? ?? 8B 40 68 C1 E8 08 }

    condition:
        any of them
}
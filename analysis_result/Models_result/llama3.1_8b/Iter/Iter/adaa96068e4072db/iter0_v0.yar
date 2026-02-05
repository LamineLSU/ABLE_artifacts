rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? 83 C4 08 52 50 FF D2 }
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 08 52 50 }
        $pattern2 = { 6A 00 5A 8B CE E8 ?? ?? ?? ?? }

    condition:
        any of them
}
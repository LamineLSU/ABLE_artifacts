rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5B 5A 8B C7 E8 57 26 00 00 }
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern2 = { 8B C7 E8 57 26 00 00 8B E5 5D C3 }

    condition:
        any of them
}
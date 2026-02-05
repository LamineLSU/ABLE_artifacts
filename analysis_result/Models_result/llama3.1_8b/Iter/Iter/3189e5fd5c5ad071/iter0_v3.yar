rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=modify,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern2 = { 66 83 F9 FF 3A D8 05 ?? ?? ?? ?? }
        $pattern3 = { 0F 84 ?? ?? ?? ?? 8B 45 ?? }

    condition:
        any of them
}
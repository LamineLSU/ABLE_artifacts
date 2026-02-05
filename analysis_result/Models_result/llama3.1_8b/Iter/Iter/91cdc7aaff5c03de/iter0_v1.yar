rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 20 57 53 53 8D 4D 84 E8 ?? ?? ?? ?? 50 68 ?? ?? ?? 57 ?? ?? ?? }
        $pattern1 = { 20 FF 15 ?? ?? ?? 02 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern2 = { 20 68 ?? ?? ?? 57 ?? ?? ?? 83 F8 20 7E 07 57 }

    condition:
        any of them
}
rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { FF 75 08 FF 08 ?? ?? ?? ?? 8B 45 ?? }
        $pattern2 = { FF 15 98 52 F4 00 FF 15 98 52 35 00 }

    condition:
        any of them
}
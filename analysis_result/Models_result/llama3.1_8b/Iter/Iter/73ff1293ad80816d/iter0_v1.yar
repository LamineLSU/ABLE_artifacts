rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { B9 ?? ?? ?? 50 E8 ?? ?? ?? ?? E9 ?? ?? ?? }
        $pattern1 = { E8 ?? ?? ?? ?? FF 75 ?? 59 FF 75 ?? FF 15 ?? ?? ?? }
        $pattern2 = { FF 15 ?? ?? ?? 33 FF 8B C7 EB 03 }

    condition:
        any of them
}
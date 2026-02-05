rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? FF FF FF 59 FF 75 ?? }
        $pattern1 = { FF 75 ?? 59 E8 ?? FF FF FF }
        $pattern2 = { FF 15 ?? ?? 41 00 FF 75 ?? 59 }

    condition:
        any of them
}
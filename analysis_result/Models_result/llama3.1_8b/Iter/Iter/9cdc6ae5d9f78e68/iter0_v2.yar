rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 40 30 2E 01 ?? FF 50 ?? }
        $pattern1 = { 8B CE E8 ?? ?? ?? ?? FF 75 08 }
        $pattern2 = { 59 FF 75 08 ?? ?? }

    condition:
        any of them
}
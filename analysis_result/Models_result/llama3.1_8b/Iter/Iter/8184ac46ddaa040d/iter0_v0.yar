rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 0F 84 ?? ?? ?? ?? FF 15 2C A1 C7 00 }
        $pattern1 = { 53 0F 84 ?? ?? ?? ?? FF 15 2C A1 32 01 }
        $pattern2 = { 50 0F 84 ?? ?? ?? ?? FF 15 8C E1 DD 00 }

    condition:
        any of them
}
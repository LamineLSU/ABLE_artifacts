rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { FF 75 08 ?? ?? ?? E8 0B 00 00 00 ?? ?? ?? FF 15 A0 F1 42 00 }
        $pattern2 = { E8 0B 00 00 00 ?? ?? ?? FF 75 08 ?? ?? ?? FF 15 A0 F1 42 00 }
        $pattern3 = { FF 15 A0 F1 42 00 ?? ?? ?? E8 0B 00 00 00 ?? ?? ?? FF 75 08 }

    condition:
        any of them
}
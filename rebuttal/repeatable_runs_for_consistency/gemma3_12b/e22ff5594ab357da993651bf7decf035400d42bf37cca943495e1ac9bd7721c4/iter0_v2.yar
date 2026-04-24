rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 B4 50 D2 00 84 C0 74 20 }
        $pattern1 = { E8 0B 00 00 00 59 FF 75 08 83 C4 08 85 C0 }
        $pattern2 = { FF 15 3C 50 D2 00 50 FF 15 40 50 D2 00 6A 08 }

    condition:
        any of them
}
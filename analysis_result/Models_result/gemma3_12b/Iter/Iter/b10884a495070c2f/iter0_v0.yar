rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 00 40 40 00 E8 90 F6 FF FF }
        $pattern1 = { FF 15 50 B0 AB 00 FF 74 24 10 }
        $pattern2 = { FF 15 18 91 AB 00 57 FF 15 D8 90 AB 00 }

    condition:
        any of them
}
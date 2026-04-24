rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 4C 24 58 E8 AB 00 00 00 50 68 D8 40 46 00 }
        $pattern1 = { 8D 4D E8 50 50 E8 19 01 00 00 50 68 D8 40 46 00 57 FF 15 34 73 45 00 }
        $pattern2 = { FF 15 7C 72 45 00 6A 01 B8 38 44 46 00 8B CE E8 19 01 00 00 50 }

    condition:
        any of them
}
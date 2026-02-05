rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 84 75 45 00 6A 3C 8D 85 94 FE FF FF }
        $pattern1 = { FF 15 40 40 44 00 8B F0 6A 08 56 FF 15 04 40 44 00 }
        $pattern2 = { FF 15 70 41 44 00 81 FF 99 02 00 00 5F 5E 7D 08 }

    condition:
        any of them
}
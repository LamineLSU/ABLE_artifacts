rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 48 8D 4C 24 60 48 89 74 24 30 45 33 C9 89 74 24 28 45 33 C0 }
        $pattern1 = { 48 8B C8 FF 15 E9 0E 00 00 48 8B CF 48 8D 54 24 40 FF 15 CB 0E 00 00 }
        $pattern2 = { FF 15 B2 0E 00 00 48 8D 95 98 01 00 00 48 8B C8 FF 15 E9 0E 00 00 }

    condition:
        any of them
}
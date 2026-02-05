rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 48 8D 4C 24 60 48 89 74 24 30 45 33 C9 89 74 24 28 45 33 C0 BA 00 00 00 C0 }
        $pattern1 = { 48 8B F8 48 83 F8 FF 74 4E 4C 8D 8D 90 01 00 00 48 89 9D 98 01 00 00 }
        $pattern2 = { 48 8B C8 FF 15 E9 0E 00 00 4C 8D 8D 90 01 00 00 48 89 74 24 20 44 8D 46 14 48 8B CF 48 8D 54 24 40 FF 15 CB 0E 00 00 }

    condition:
        any of them
}
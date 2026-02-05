rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 48 8D 4C 24 60 48 89 74 24 30 }
        $pattern1 = { FF 15 F1 0E 00 00 48 8B F8 }
        $pattern2 = { 48 8D 95 98 01 00 00 48 8B C8 }

    condition:
        any of them
}
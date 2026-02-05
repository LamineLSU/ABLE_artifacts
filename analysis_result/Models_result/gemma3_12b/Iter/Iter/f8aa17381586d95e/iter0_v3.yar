rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 35 6A 00 51 8D B0 74 0C 00 00 56 50 E8 44 09 00 00 }
        $pattern1 = { 8B 45 08 8B 48 10 56 6A 36 6A 00 51 8D B0 7C 0C 00 00 56 50 E8 44 09 00 00 }
        $pattern2 = { 6E FB 9B D4 0D 28 35 E2 8C EF 57 }

    condition:
        any of them
}
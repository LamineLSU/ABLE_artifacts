rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 18 8A 02 55 8B EC 8B 45 08 }
        $pattern1 = { 56 6A 36 6A 00 51 8D B0 A0 0C 00 00 }
        $pattern2 = { 27 AE D4 5D 44 }

    condition:
        any of them
}
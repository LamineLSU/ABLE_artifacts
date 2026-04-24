rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 80 C1 58 88 4C 04 90 }
        $pattern1 = { 75 DD 89 E0 8D 4C 24 18 }
        $pattern2 = { 89 C6 21 D6 09 C2 8D 0C 36 }

    condition:
        any of them
}
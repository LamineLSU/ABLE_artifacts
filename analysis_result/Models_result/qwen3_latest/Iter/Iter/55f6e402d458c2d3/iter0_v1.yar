rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 3C 22 75 ?? 41 8A 11 }
        $pattern1 = { 75 ?? 3C 20 74 11 }
        $pattern2 = { 84 D2 75 ?? 41 8A 11 84 D2 74 11 41 8A 11 }

    condition:
        any of them
}
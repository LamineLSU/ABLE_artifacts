rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 4D 0C 83 C4 14 52 52 8B 16 50 }
        $pattern1 = { 8B 55 0C 8B 45 10 8B 4D 0C 83 C4 14 }
        $pattern2 = { 55 8B EC 8B 45 08 8B 88 18 }

    condition:
        any of them
}
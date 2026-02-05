rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 55 20 50 8B 45 1C 51 8B 4D 18 52 }
        $pattern1 = { 8B 55 14 50 8B 45 10 8B 45 28 8B 45 28 51 }
        $pattern2 = { 52 8B 55 2C 50 8B 45 34 8B 4D 30 83 C4 14 }

    condition:
        any of them
}
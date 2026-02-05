rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 55 14 50 8B 45 10 50 8B 45 1C }
        $pattern1 = { 8B 55 2C 50 8B 45 28 50 8B 45 20 }
        $pattern2 = { 55 8B 55 14 50 8B 45 10 50 }

    condition:
        any of them
}
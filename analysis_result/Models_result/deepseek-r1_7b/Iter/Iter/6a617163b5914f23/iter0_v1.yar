rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 42 46 E9 42 47 0A }
        $pattern1 = { 40 10 33 40 10 3B }
        $pattern2 = { 48 D1 0C 48 D1 0F 48 D1 15 48 D1 16 }

    condition:
        any of them
}
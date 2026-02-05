rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting early exit decisions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5B 8D 84 33 3A 7C 00 00 }
        $pattern1 = { 6A 40 57 66 5E 7D 6C 66 }
        $pattern2 = { FC 00 00 00 00 00 00 00 }

    condition:
        (any_of($pattern0) OR any_of($pattern1) OR any_of($pattern2))
}
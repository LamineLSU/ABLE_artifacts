rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific known points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B C7 74 12 6A 5B }
        $pattern1 = { 6A 40 53 53 B9 E5 F8 }
        $pattern2 = { 3D 00 10 0C E8 4B 17 00 00 }

    condition:
        (any_of($pattern0) OR any_of($pattern1) OR any_of($pattern2))
}
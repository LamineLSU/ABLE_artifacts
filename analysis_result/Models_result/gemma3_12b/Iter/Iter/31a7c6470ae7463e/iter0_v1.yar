rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 3D 2D 92 F6 80 74 CF }
        $pattern1 = { 5C 3D 2D 92 F6 80 5E }
        $pattern2 = { 74 CF 46 B7 92 6A 35 }

    condition:
        any of them
}
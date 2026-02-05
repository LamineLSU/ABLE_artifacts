rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 3C 40 ?? ?? ?? ?? }
        $pattern1 = { FF 75 ?? A1 41 ?? }
        $pattern2 = { E8 B4 5C 20 ?? ?? ?? }

    condition:
        any of them
}
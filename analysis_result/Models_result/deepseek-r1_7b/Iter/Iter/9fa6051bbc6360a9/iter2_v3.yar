rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - refined"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC ?? ?? ?? ?? FF D2 }
        $pattern1 = { 3D 00 10 00 00 74 12 8B 4D ?? }
        $pattern2 = { 00 00 00 63 C4 55 8B EC DC }
}

condition:
    (any of the three patterns)
rule Bypass_Sample
{
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 8B 45 ?? ?? ?? FF 75 08 ?? ?? ?? ?? FF 15 A0 F1 42 00 }
        $pattern1 = { FF 75 08 E8 0B ?? ?? ?? ?? FF 15 3C F1 42 00 ?? ?? ?? }
        $pattern2 = { FF 75 08 E8 F7 25 00 00 ?? ?? ?? ?? FF 15 40 F1 42 00 }

    condition:
        any of them
}
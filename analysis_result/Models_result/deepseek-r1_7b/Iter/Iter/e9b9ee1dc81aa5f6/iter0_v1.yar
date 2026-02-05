rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns from exit points",
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 4A 24 50 00 59 7F 0A }
        $pattern1 = { 8D 4A 24 30 59 E8 AB 00 00 00 68 D8 40 46 00 57 }
        $pattern2 = { FF 15 7C 72 45 68 D8 40 E8 46 E8 AB 00 00 00 }

    condition:
        any of them
}
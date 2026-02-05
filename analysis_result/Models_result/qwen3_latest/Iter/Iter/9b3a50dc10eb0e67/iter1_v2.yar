rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 74 24 04 E8 ?? ?? ?? ?? }
        $pattern1 = { FF 15 5C E0 40 00 }
        $pattern2 = { FF 15 A8 01 B8 00 }

    condition:
        any of them
}
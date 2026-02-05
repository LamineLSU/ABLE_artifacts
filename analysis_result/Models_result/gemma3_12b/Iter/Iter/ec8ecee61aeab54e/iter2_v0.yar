rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 4C 24 1C E8 AB 00 00 00 }
        $pattern1 = { 00 40 BC 30 83 F8 20 }
        $pattern2 = { FF 15 28 63 45 00 }

    condition:
        any of them
}
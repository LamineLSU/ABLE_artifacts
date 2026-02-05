rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 48 8D 95 98 01 00 00 }
        $pattern1 = { FF 15 E9 0E 00 00 }
        $pattern2 = { FF 15 B2 0E 00 00 }

    condition:
        any of them
}
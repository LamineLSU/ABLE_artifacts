rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 F1 0E 00 00 }
        $pattern1 = { 48 83 F8 FF 74 4E }
        $pattern2 = { FF 15 E9 0E 00 00 }

    condition:
        any of them
}
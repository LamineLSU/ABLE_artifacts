rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 E8 A5 10 00 00 A3 C9 40 40 00 }
        $pattern1 = { E8 95 10 00 00 A3 C5 40 40 00 6A 0A }
        $pattern2 = { FF 35 C5 40 40 00 6A 00 FF 35 C9 40 40 00 }

    condition:
        any of them
}
rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? 44 60 08 83 F8 11 74 05 }
        $pattern1 = { FF 15 ?? 44 60 00 85 C0 75 07 }
        $pattern2 = { FF 15 50 60 44 00 }

    condition:
        any of them
}
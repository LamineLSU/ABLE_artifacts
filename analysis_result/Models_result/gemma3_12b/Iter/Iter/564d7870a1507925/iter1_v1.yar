rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 E8 B0 C8 F9 FF }
        $pattern1 = { 66 81 3C 24 E4 07 }
        $pattern2 = { 6A 00 E8 D1 C7 F9 FF }

    condition:
        any of them
}
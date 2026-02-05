rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - focuses on specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 41 38 60 FF 75 D4 44 41 00 75 32 00 41 39 00 }
        $pattern1 = { 00 41 38 A4 FF 15 90 44 41 00 FF 35 D4 B0 41 00 00 41 39 00 }
        $pattern2 = { 00 41 38 E5 FF 15 8C 44 41 00 6A 09 00 41 B0 C8 }
    condition:
        any of them
}
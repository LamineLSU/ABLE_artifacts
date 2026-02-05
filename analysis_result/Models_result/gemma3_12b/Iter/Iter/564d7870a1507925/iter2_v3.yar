rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 C4 F0 8B D8 54 E8 B0 C8 F9 FF }
        $pattern1 = { 6A 00 81 FB 01 00 00 80 0F 94 C0 8B D8 }
        $pattern2 = { 6A 00 E8 6B 25 FE FF 8B C3 83 C4 10 }

    condition:
        any of them
}
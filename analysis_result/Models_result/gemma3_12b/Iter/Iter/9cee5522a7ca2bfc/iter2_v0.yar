rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 E9 04 77 F1 01 CF E9 4C FF FF FF }
        $pattern1 = { 8B 5F 04 8D 84 30 00 E0 00 00 01 F3 50 }
        $pattern2 = { 83 E9 01 73 D8 8D BE 00 C0 00 00 }

    condition:
        any of them
}
rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 C4 83 C0 01 89 45 C4 }
        $pattern1 = { 8B 55 C4 8B 45 E4 8B 0C 90 51 FF 15 F0 50 61 00 }
        $pattern2 = { 83 3D 5C 42 61 00 00 E8 EF 9C FF FF }

    condition:
        any of them
}
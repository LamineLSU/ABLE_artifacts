rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { 8B 85 F0 FE FF FF 89 9D F0 FE FF FF 8B CE E8 74 FA FF FF }
        $pattern2 = { 8B 85 F0 FE FF FF 03 C3 BA 04 01 00 00 03 C1 B9 42 8C B9 00 50 E8 E3 FA FF FF }

    condition:
        any of them
}
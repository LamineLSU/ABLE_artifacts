rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { 8D 95 F0 FE FF FF 89 9D F0 FE FF FF 8B CE E8 74 FA FF FF }
        $pattern1 = { 85 C0 0F 84 33 FD FF FF 8D 85 F0 FE FF FF 8B CC E8 E3 FA FF FF }
        $pattern2 = { 83 F8 01 74 12 8B 4D F8 03 C3 BA 04 01 00 00 }

    condition:
        any of them
}
rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 85 F0 FE FF FF 8D 8D F8 FE FF FF 03 C3 BA 04 01 00 00 03 C1 B9 42 8C E8 00 50 E8 E3 FA FF FF }
        $pattern1 = { 8B 85 F0 FE FF FF 8D 8D F8 FE FF FF 03 C3 BA 04 01 00 00 03 C1 B9 42 8C 0C 00 50 E8 E3 FA FF FF }
        $pattern2 = { 8B 85 F0 FE FF FF 8D 8D F8 FE FF FF 03 C3 BA 04 01 00 00 03 C1 B9 42 8C DE 00 50 E8 E3 FA FF FF }

    condition:
        any of them
}
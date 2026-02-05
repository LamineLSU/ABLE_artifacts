rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 85 F0 FE FF FF 8B 8D F8 FE FF FF 03 C3 BA 04 01 00 00 03 C1 B9 42 8C 22 00 50 E8 E3 FA FF FF }
        $pattern1 = { 8B FF 55 8B EC FF 75 08 FF 15 AC B0 41 00 }
        $pattern2 = { 8B FF 55 8B EC E8 07 26 00 00 83 F8 01 74 20 FF 75 08 FF 15 3C E1 35 01 }

    condition:
        any of them
}
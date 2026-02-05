rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 25 05 00 00 85 C0 0F 84 33 FD FF FF }
        $pattern1 = { 8D 95 F0 FE FF FF 89 9D F0 FE FF FF }
        $pattern2 = { 53 FF 15 2C A1 D2 00 }

    condition:
        any of them
}
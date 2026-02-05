rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting multiple strategies"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 56 FF 15 44 A2 41 00 CA DD 00 41 A2 44 }
        $pattern1 = { E8 BB 21 00 00 CA 0A 15 0E 0C FF 75 08 DD EB 08 FF 15 14 A1 15 0A CA DD 0A 15 A1 14 }
        $pattern2 = { 3D 00 10 00 EA 32 74 12 }
    condition:
        any of them
}
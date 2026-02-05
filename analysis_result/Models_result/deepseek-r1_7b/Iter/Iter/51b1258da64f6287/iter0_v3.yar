rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE ?? E8 4B 17 00 00 ?? FF 88 85 F0 FE FF FF ?? }
        $pattern1 = { E8 C8 FF FF FF ?? FF 15 AC B0 41 00 ?? }
        $pattern2 = { F9 E8 08 1D ?? 8B E5 ?? C3 }

    condition:
        any of them
}
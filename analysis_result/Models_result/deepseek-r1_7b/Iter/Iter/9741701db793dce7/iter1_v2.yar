rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specifically targeting conditional exit checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { E8 E0 A2 FF FF 3D 00 74 12 8B 4D F8 }
        $pattern2 = { FF 15 14 28 43 00 00 00 00 00 00 00 }

    condition:
        any of them
}
rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B ?? ?? FF 15 20 75 45 00 }
        $pattern1 = { C7 85 94 FE FF FF 3C 00 00 00 DD EB 00 00 01 6C 00 00 00 3C E8 ?? ?? ?? ?? }
        $pattern2 = { 83 F8 01 74 12 8B 4D F8 53 50 E8 B1 25 02 00 CA 00 43 4D 30 }

    condition:
        any of them
}
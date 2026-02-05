rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { 3D 00 10 00 00 10 00 00 00 01 10 00 00 00 5B 89 9D F0 FE FF FF E8 A1 2C }
        $pattern2 = { 85 C0 74 12 6A 5B 5A 8B CE B9 42 8C E8 00 }

    condition:
        any of them
}
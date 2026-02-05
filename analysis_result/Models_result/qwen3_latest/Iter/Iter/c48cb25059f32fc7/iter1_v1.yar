rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 85 94 FD FF FF E8 3D CF FF FF }
        $pattern1 = { 33 C0 89 85 E8 FE FF FF E8 D1 88 FE FF }
        $pattern2 = { 6A 00 E8 B4 AE FE FF }

    condition:
        any of them
}
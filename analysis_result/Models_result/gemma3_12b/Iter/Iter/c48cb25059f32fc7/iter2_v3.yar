rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 85 94 FD FF FF BA 03 00 00 00 E8 F5 B9 FE FF }
        $pattern1 = { E8 3D CF FF FF 89 85 E8 FE FF FF 8D 95 78 FD FF FF }
        $pattern2 = { 8D 95 78 FD FF FF 33 C0 E8 D1 88 FE FF 8B 95 78 FD FF FF }

    condition:
        any of them
}
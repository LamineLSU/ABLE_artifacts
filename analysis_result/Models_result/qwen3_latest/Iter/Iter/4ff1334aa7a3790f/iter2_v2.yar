rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 25 05 00 00 85 C0 0F 84 33 FD FF FF }
        $pattern1 = { E8 3D 04 00 00 85 C0 0F 84 33 FD FF FF }
        $pattern2 = { E8 4D 00 00 00 50 E8 3D 00 00 00 }

    condition:
        any of them
}
rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 8D 85 F4 FD FF FF 33 C0 }
        $pattern1 = { 68 AC A4 41 00 8D 85 94 FD FF FF BA 03 00 00 00 E8 F5 B9 FE FF }
        $pattern2 = { 83 EC 20 3D 00 10 00 00 0F 82 ?? ?? ?? }

    condition:
        any of them
}
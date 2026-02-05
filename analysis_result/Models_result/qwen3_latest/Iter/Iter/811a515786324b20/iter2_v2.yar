rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 AC A4 41 00 8D 85 94 FD FF FF BA 03 00 00 00 E8 F5 B9 FE FF }
        $pattern1 = { E8 D1 88 FE FF 8B 45 FC 83 F8 01 74 12 }
        $pattern2 = { E8 3A CD FF FF BA 02 00 00 00 E8 2E CD FF FF 85 C0 74 0C }

    condition:
        any of them
}
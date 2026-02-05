rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { BA 03 00 00 00 E8 F5 B9 FE FF }
        $pattern1 = { 8B 85 94 FD FF FF E8 3D C3 FF FF }
        $pattern2 = { A1 64 B5 41 00 8B 00 FF D0 }

    condition:
        any of them
}
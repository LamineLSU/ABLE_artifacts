rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 AC A4 41 00 E8 F5 B9 FE FF BA 03 00 00 00 }
        $pattern1 = { 8B 85 94 FD FF FF E8 3D CF FF FF BA 03 00 00 00 }
        $pattern2 = { 8D 95 78 FD FF FF E8 4D B9 FE FF BA 03 00 00 00 }

    condition:
        any of them
}
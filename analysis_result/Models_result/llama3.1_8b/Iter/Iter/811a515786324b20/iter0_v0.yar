rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 AC A4 41 00 8D 85 94 FD FF FF EA EA DD EB 00 00 02 6C }
        $pattern1 = { E8 F5 B9 FE FF CA 00 40 3E 1C }
        $pattern2 = { BA 03 00 00 00 ED 00 00 00 03 }

    condition:
        any of them
}
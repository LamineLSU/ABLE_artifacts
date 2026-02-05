rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 95 DB 0D 74 8B FF 55 8B EC }
        $pattern1 = { E8 94 DB 8D 74 90 C6 44 24 26 00 B8 88 00 00 00 }
        $pattern2 = { E8 34 6F 66 74 CC CC CC }

    condition:
        any of them
}
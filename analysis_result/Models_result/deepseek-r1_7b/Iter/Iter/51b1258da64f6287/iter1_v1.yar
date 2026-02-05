rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 9D 61 7A EA EA 00 9D 61 7C 00 9D 61 90 }
        $pattern1 = { 00 9D 61 83 E8 25 05 00 00 CA 00 9D 66 7F 00 9D 61 8A 00 9D 5E 83 }
        $pattern2 = { 00 9D 61 B7 EA EA 00 9D 61 B9 BA 04 01 00 00 }

    condition:
        any of them
}
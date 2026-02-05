rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 E8 61 7A 00 E8 61 7C 00 E8 61 7E 00 E8 61 80 00 E8 61 81 00 E8 61 83 }
        $pattern1 = { 00 E8 61 B5 00 E8 61 B7 00 E8 61 B9 00 E8 61 BA 00 E8 61 BE 00 E8 61 C0 }
        $pattern2 = { 00 E8 61 D4 00 E8 61 D7 00 E8 61 DA 00 E8 61 DB 00 E8 61 DC 00 E8 61 E0 }

    condition:
        (any of the patterns match)
}
rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with specific patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 B7 61 7A 85 C0 00 B7 61 7C 74 12 00 B7 61 7E 6A 5B 00 B7 61 80 5A 00 B7 61 81 8B 45 FC }
        $pattern1 = { 00 B7 61 C5 53 00 B7 61 D0 33 DB 00 B7 61 E2 6A 40 00 B7 61 DA 53 00 B7 61 DB 68 40 11 B7 00 }
        $pattern2 = { 00 B7 44 B9 DC 00 B7 85 88 5F }

    condition:
        (any of the three patterns match)
}
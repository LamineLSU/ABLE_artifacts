rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 8B 45 FC 00 02 A9 FF 15 50 A0 B8 00 }
        $pattern1 = { 85 FF 74 39 00 B3 A2 9B }
        $pattern2 = { 74 14 53 00 B3 A2 D6 }

    condition:
        any of them
}
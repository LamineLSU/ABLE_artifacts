rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting specific decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 E8 25 05 00 00 }
        $pattern1 = { EB 03 E9 B5 FC FF FF }
        $pattern2 = { 85 C0 FF 15 2C A1 8E 00 E8 B3 03 00 00 }

    condition:
        any of them
}
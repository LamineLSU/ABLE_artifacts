rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 6A 5B 5A E8 25 05 00 00 01 39 66 7F }
        $pattern1 = { 85 C0 0F 84 17 4B 6A 5B ?? E8 4B 17 00 00 01 39 44 B9 53 53 }
        $pattern2 = { 85 C0 0F 84 17 4B 6A 5B ?? E9 B5 FC FF FF 01 39 5E 85 53 }

    condition:
        any of them
}
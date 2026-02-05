rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with specific decision checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 00 00 00 5B }
        $pattern1 = { 83 F8 01 74 8B 45 FC }  // Conditional comparison and jump
        $pattern2 = { E8 4B 17 00 CA 00 1A 44 B9 }  // Specific call sequence

    condition:
        any of them
}
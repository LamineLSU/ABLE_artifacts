rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 00 00 00 5B }
        $pattern1 = { 85 C0 74 12 00 04 61 90 }
        $pattern2 = { E8 57 26 00 00 CA 00 04 6C E0 }
}

condition:
    any of the patterns match in the trace
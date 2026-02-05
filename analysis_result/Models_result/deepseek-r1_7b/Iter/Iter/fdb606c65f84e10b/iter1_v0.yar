rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 12 8B 4D F8 }
        $pattern1 = { 5A 6A 5B 5E 9C 5B 5E }
        $pattern2 = { 85 C0 E8 B3 00 FE FF }
}

condition:
    (any of them)
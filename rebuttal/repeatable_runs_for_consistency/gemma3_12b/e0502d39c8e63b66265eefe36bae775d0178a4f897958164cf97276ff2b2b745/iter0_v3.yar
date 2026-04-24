rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 51 51 E8 5A 29 01 00 } // Trace 1, 004067D7
        $pattern1 = { 8B 35 30 A2 41 00 FF D6 } // Trace 2, 004167E7
        $pattern2 = { 74 13 68 14 A9 41 00 } // Trace 6, 004069D3

    condition:
        any of them
}
rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 33 D2 83 FA 05 75 02 EB 02 } // Skip division, comparison and loop back
        $pattern1 = { F7 F1 83 FA 05 75 02 } // Skip division and comparison
        $pattern2 = { 83 FA 05 75 02 EB 02 } // Skip comparison and loop back

    condition:
        any of them
}
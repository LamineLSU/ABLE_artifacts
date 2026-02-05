rule Bypass_Sample_Evolved {
    meta:
        description = "Evasion bypass targeting API and early checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }
        $pattern1 = { 85 C0 3C 9D 6A 40 E8 41 }
        $pattern2 = { EB 03 F8 F0 F1 D7 C4 5F }

    condition:
        any of them
}
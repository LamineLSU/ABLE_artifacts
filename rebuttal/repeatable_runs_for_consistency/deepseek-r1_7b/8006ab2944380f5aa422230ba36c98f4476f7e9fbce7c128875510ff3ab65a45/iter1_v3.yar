rule Bypass_Sample_Evasion {
    meta:
        description = "Evasion bypass analysis for specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 41 E8 BC 52 53 41 E8 D0 5E 8B }
        $pattern1 = { 41 E9 37 5E 5D 5F 8B 82 }
        $pattern2 = { 5A 8D 5E 06 8B 5F }

    condition:
        any of them
}
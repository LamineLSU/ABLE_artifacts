rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = {E8 CE ?? ?? ???}  // E8 instruction followed by CE and three wildcards
        $pattern1 = {74 ?? ?? ?? ????}  // 74 with four wildcards beyond
        $pattern2 = {0F 84 ?? ?? ???}   // 0F 84 followed by three wildcards
}
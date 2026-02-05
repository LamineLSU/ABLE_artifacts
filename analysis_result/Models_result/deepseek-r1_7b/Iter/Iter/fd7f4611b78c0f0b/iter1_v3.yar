rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,cap wild=True"
    
    strings:
        $pattern0 = { 48 57 39 CE ?? CE 1F 26 00 }
        $pattern1 = { E8 25 05 00 00 ?? CE 1F 26 00 }
        $pattern2 = { 40 E7 F1 ?? CE 1F 26 00 }
    
    condition:
        (any of them)
}
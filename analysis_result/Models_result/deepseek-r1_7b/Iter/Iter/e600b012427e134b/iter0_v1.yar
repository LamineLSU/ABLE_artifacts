rule Bypass_Sample {
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 75 C6 E1 01 ?? ?? 8B EC 74 20 }
        $pattern1 = { 55 ?? ?? 74 20 ?? ?? 8B CE E8 ?? } 
        $pattern2 = { 6A ?? ?? 51 E7 3F 7B 3D 40 EA }
    
    condition:
        any of them
}
rule Bypass_Sample {
    meta:
        description = "Evasion bypass for function calls and conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"
    
    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 64 A1 5A 8B CE E8 ?? ?? ?? ?? 83 F8 00 }
        $pattern2 = { 64 A1 5A 8B CE E8 ?? ?? ?? ?? FF 15 08 }
    
    condition:
        any_of them
}
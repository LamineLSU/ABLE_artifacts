rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns targeting ExitProcess calls."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
    
    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 00 00 00 }
        $pattern1 = { 6A ?? 5A 8B CE ?? ?? ?? ?? ?? 85 C0 00 00 00 }
        $pattern2 = { E8 C7 F0 ?? 74 00 00 00 00 00 9D E1 FF FF FF }
    
    condition:
        any of them
}
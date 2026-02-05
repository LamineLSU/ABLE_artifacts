rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"
    
    strings:
        $pattern0 = { 55 8B FF E8 ?? } // First call after push ebp and mov
        $pattern1 = { 59 FF 75 08 E8 ?? } // After pop ecx and subsequent push
        $pattern2 = { E8 FF FF FF 59 FF 75 08 } // Second call and surrounding context
    condition:
        any of them
}
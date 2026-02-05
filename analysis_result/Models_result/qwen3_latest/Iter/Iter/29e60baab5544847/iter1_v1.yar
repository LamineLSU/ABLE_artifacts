rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "[CALL_TEST_JE] evasion bypass - evolved"  
        pattern_type = "CALL_TEST_JE"  
        confidence = "60"  
        iteration = "1"  
        cape_options = "bp0=$pattern+0,action0=skip,count=0"  

    strings:  
        $pattern = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }  

    condition:  
        $pattern  
}
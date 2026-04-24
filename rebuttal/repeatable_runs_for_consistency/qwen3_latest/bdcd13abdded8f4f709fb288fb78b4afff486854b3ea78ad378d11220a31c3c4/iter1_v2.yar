rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { 52 ?? ?? ?? ?? ?? 8B 16 ?? ?? ?? ?? FF D2 }  // push edx, mov edx, call edx  
        $pattern1 = { FF D2 ?? ?? ?? ?? C3 }                        // call edx, ret  
        $pattern2 = { 57 ?? ?? ?? ?? FF D2 }                        // push edi, call edx  

    condition:  
        any of them  
}
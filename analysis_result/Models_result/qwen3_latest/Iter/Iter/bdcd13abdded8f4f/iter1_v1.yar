rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { FF D2 5E 5D C3 ?? ?? ?? } // Call RtlAllocateHeap + stack cleanup  
        $pattern1 = { E1 7D 63 F6 ?? ?? ?? ?? } // LOOPE + ARPL obfuscation  
        $pattern2 = { 8D B6 C7 00 00 00 ?? ?? } // LEA with hardcoded offset  

    condition:  
        any of them  
}
rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { FF D2 5E 5E 5D C3 }  // Call RtlAllocateHeap + ret sequence  
        $pattern1 = { E8 44 09 00 00 8B 45 08 }  // Indirect call + data access  
        $pattern2 = { BF 00 D3 C5 21 8B 45 08 }  // Memory initialization + data access  

    condition:  
        any of them  
}
rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { 52 8B 16 50 51 FF D2 }  // Call to RtlAllocateHeap  
        $pattern1 = { 0A 04 B6 77 B8 6F C1 84 }  // Conditional jump + memory ops  
        $pattern2 = { 8D B0 74 0C 00 00 }         // LEA instruction for obfuscation  

    condition:  
        any of them  
}
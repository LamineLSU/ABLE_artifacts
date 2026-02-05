rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { 83 EF 01 85 FF 74 39 }  // sub edi, 01h + test edi, edi + je  
        $pattern1 = { E8 08 8D 02 00 50 FF 15 40 A0 20 00 }  // call 001E21E6h + push + call HeapFree  
        $pattern2 = { 83 EF 01 FF 15 44 A0 20 00 }  // sub edi, 01h + call GetProcessHeap  

    condition:  
        any of them  
}
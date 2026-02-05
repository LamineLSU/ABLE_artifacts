rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { 52 FF D2 5E 5D C3 } // push edx, call edx, pop esi/ebp, ret  
        $pattern1 = { 56 50 E8 74 0A 00 00 } // push esi, push eax, call 0041EB27h  
        $pattern2 = { 50 FF D2 5E 5D C3 } // push eax, call edx, pop esi/ebp, ret  

    condition:  
        any of them  
}
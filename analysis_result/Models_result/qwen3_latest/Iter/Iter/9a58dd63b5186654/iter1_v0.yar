rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { FF 15 ?? ?? ?? ?? }  // CALL to API (address varies)  
        $pattern1 = { 85 C9 B8 00 00 00 }   // test ecx, ecx followed by mov eax  
        $pattern2 = { 50 83 F8 11 74 05 }   // push eax + cmp eax, 11h + je  

    condition:  
        any of them  
}
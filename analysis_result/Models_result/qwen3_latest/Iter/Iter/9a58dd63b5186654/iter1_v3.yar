rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { FF 15 ?? ?? ?? ?? 8B F0 }  // VirtualAllocExNuma call + mov esi, eax  
        $pattern1 = { 8B F0 83 F8 11 74 05 }     // mov esi, eax + cmp eax, 11h + je  
        $pattern2 = { 8B F0 85 C0 75 07 }        // mov esi, eax + test eax, eax + jne  

    condition:  
        all of them  
}
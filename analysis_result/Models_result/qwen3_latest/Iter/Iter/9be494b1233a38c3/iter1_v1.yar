rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { FF 15 ?? ?? ?? ?? 83 F8 11 74 05 } // VirtualAlloc call + CMP EAX, 11h + JE  
        $pattern1 = { 85 C0 0F 85 ?? ?? ?? ?? } // TEST EAX, EAX + JNE  
        $pattern2 = { 53 56 57 83 EC 04 83 EC 0C 8D 44 24 0C FF D0 } // Initial push + setup before VirtualAlloc  

    condition:  
        any of them  
}
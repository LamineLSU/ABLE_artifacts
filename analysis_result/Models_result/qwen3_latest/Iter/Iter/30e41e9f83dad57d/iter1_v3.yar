rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { FF 15 ?? ?? ?? ?? 85 C0 75 07 } // Call + test + jne sequence  
        $pattern1 = { FF 15 94 37 61 00 }              // Exact VirtualAllocExNuma call  
        $pattern2 = { 56 FF 15 ?? ?? ?? ?? }           // Push esi + call sequence  

    condition:  
        any of them  
}
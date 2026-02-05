rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { 85 C0 74 12 8B CE E8 ?? ?? ?? ?? }  // test+je+mov+call sequence  
        $pattern1 = { B9 42 8C 31 01 E8 ?? ?? ?? ?? }      // mov+call sequence  
        $pattern2 = { 33 C9 E8 ?? ?? ?? ?? }               // xor+call sequence  

    condition:  
        any of them  
}
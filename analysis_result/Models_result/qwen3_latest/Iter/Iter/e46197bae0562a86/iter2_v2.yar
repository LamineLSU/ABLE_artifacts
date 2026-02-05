rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { 85 C0 74 12 6A 5B }  // test+je+push (early control flow)  
        $pattern1 = { 85 C0 0F 84 33 FD FF FF }  // test+je (later conditional check)  
        $pattern2 = { FF 15 2C A1 94 00 }  // call to ExitProcess (termination point)  

    condition:  
        any of them  
}
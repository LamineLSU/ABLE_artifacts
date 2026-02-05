rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { 85 C0 74 12 8D 95 FC 00 00 00 }  // test+je+lea (specific early logic)  
        $pattern1 = { E8 ?? ?? ?? ?? 85 C0 }            // call+test (flexible offset)  
        $pattern2 = { FF 15 88 A0 01 01 85 C0 0F 84 ?? ?? ?? ?? }  // API call+test+je (specific API flow)  

    condition:  
        any of them  
}
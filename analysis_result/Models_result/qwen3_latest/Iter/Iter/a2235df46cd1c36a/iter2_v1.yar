rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { 85 C0 74 12 ?? ?? ?? ?? }  // test eax, eax + je (evasion check)  
        $pattern1 = { FF 15 ?? ?? ?? ?? }         // call dword ptr [address] (ExitProcess)  
        $pattern2 = { 33 DB BA 21 05 00 00 53 6A 40 53 68 40 11 06 00 }  // xor+mov+push sequence  

    condition:  
        any of them  
}
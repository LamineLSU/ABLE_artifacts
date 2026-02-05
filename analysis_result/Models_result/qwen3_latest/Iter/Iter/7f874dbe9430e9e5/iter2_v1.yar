rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { E8 C8 FF FF FF }  // Early exit hook call  
        $pattern1 = { FF 15 AC B0 41 00 }  // ExitProcess call  
        $pattern2 = { 55 8B EC FF 75 08 }  // Stack setup before exit  

    condition:  
        any of them  
}
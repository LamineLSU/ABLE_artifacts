rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 }  // Call followed by test eax  
        $pattern1 = { 85 C0 74 12 8B 45 FC }  // Test, je, and mov (stack offset)  
        $pattern2 = { FF 15 ?? ?? ?? ?? }     // ExitProcess call (indirect)  

    condition:  
        any of them  
}
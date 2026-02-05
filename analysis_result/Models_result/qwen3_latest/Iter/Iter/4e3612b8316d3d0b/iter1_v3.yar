rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { 85 C0 74 12 8D 54 24 F4 }  // test eax, eax + je + lea  
        $pattern1 = { 85 C0 0F 84 33 FD FF FF }  // test eax, eax + je (offset)  
        $pattern2 = { E8 25 05 00 00 8B 4D F8 }  // call + mov ecx, [ebp-08]  

    condition:  
        any of them  
}
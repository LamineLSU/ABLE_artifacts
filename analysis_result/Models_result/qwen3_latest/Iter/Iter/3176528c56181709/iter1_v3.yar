rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { FF D2 0D 0C 38 AB 22 3D 99 EC 6D 6B }  
        $pattern1 = { 8D B0 74 0C 00 00 56 E8 44 09 00 00 }  
        $pattern2 = { 3D 99 EC 6D 6B 1E 6B 07 55 }  

    condition:  
        any of them  
}
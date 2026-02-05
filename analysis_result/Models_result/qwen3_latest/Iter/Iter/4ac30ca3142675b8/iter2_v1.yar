rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { 52 8B 16 50 51 FF D2 }  
        $pattern1 = { 50 50 E8 74 0A 00 00 }  
        $pattern2 = { 83 C2 55 E5 62 7B 74 }  

    condition:  
        any of them  
}
rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { 52 8B 16 50 51 FF D2 }  
        $pattern1 = { 83 C0 04 78 12 }  
        $pattern2 = { E8 ?? ?? ?? ?? }  

    condition:  
        any of them  
}
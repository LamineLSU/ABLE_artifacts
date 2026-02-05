rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+6,action0=skip,bp1=$pattern1+8,action1=skip,bp2=$pattern2+10,action2=skip,count=0"  

    strings:  
        $pattern0 = { FF 15 ?? ?? ?? ?? }  // CALL to ExitProcess  
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }  // TEST EAX + JE  
        $pattern2 = { A1 88 85 3B 01 85 C0 }  // MOV + TEST EAX  

    condition:  
        any of them  
}
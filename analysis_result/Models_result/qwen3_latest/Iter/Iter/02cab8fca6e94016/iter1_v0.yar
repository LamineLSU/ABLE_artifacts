rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { 85 C0 74 12 6A 5B } // TEST EAX/EAX + JE + PUSH  
        $pattern1 = { 85 C0 0F 84 33 FD FF } // TEST EAX/EAX + JE (offset)  
        $pattern2 = { FF 15 80 10 00 00 } // CALL ExitProcess (address)  

    condition:  
        any of them  
}
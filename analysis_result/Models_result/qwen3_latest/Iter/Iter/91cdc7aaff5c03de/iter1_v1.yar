rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { 80 3D 86 0A 46 00 00 0F 85 C3 00 00 00 } // cmp+jne evasion check  
        $pattern1 = { E8 16 A5 FF FF 50 FF 15 DC 91 44 00 } // call to DeleteFileW (hidden import)  
        $pattern2 = { 33 DB FF 24 B5 2B DF 40 00 } // jump table (control flow)  

    condition:  
        any of them  
}
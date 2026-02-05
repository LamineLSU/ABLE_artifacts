rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { E8 B7 B2 00 00 83 F8 01 74 20 }  // CALL + CMP + JE  
        $pattern1 = { C1 E8 08 A8 01 75 10 }         // SHR + TEST + JNE  
        $pattern2 = { 59 FF 75 08 FF 15 A8 30 2E 01 }   // POP + PUSH + ExitProcess call  

    condition:  
        any of them  
}
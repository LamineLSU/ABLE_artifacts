rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { 8B 16 FF D2 5E 5D C3 }  // mov edx, [esi] | call edx | pop esi | pop ebp | ret  
        $pattern1 = { E8 44 09 00 00 }         // call 00418DB0 (relative offset)  
        $pattern2 = { D7 4E 52 80 F5 87 }       // xlatb | dec esi | push edx | xor ch, 0x87  

    condition:  
        any of them  
}
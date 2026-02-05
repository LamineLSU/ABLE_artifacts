rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // test eax, eax + je  
        $pattern1 = { E8 25 05 00 00 85 C0 0F 84 ?? ?? ?? ?? }  // call + test/je sequence  
        $pattern2 = { FF 15 88 A0 04 01 FF 15 2C A1 04 01 }  // CloseHandle + ExitProcess calls  

    condition:  
        any of them  
}
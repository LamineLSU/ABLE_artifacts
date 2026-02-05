rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { FF 15 ?? ?? ?? ?? 85 C0 74 10 }  // CALL IsWindowVisible + TEST EAX + JE  
        $pattern1 = { FF 15 ?? ?? ?? ?? EB 38 }         // CALL TrackPopupMenu + JMP  
        $pattern2 = { FF 15 ?? ?? ?? ?? 68 00 00 00 00 }  // CALL Shell_NotifyIconA + PUSH 0  

    condition:  
        any of them  
}
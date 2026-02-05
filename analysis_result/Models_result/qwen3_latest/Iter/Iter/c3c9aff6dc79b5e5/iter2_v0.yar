rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { FF 15 70 44 41 00 85 C0 74 10 }  // API call + conditional check  
        $pattern1 = { FF 15 D0 44 41 00 }               // TrackPopupMenu API call  
        $pattern2 = { FF 15 38 41 41 00 }               // ExitProcess API call  

    condition:  
        any of them  
}
rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? } // Call + mov eax, [ebp-...]  
        $pattern1 = { E8 ?? ?? ?? ?? 8B 4D FC } // Call + mov ecx, [ebp-04]  
        $pattern2 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? } // Push + call (address variation)  

    condition:  
        any of them  
}
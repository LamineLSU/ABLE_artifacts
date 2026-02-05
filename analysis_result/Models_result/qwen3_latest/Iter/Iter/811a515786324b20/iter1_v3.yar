rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { E8 ?? ?? ?? ?? 8B 45 ?? }  // Call to 00403E1Ch + mov eax  
        $pattern1 = { E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? }  // Call to 00403D3Ch + mov dword  
        $pattern2 = { E8 ?? ?? ?? ?? 8B 55 ?? }  // Call to 00402754h + mov edx  

    condition:  
        any of them  
}
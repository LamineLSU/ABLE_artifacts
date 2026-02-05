rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { 33 FF 8B 4D FC EB 03 }  // xor edi, edi + mov ecx + jmp  
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }  // test eax + je + mov  
        $pattern2 = { A1 88 85 A3 00 85 C0 }  // mov [00A38588h] + test eax  

    condition:  
        any of them  
}
rule Bypass_Sample_Evolved  
{  
    meta:  
        description = "Evasion bypass rule - evolved"  
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"  

    strings:  
        $pattern0 = { 50 51 E8 ?? ?? ?? ?? } // push eax, push ecx, call edx (RtlAllocateHeap)  
        $pattern1 = { 8B 45 10 50 51 8D 56 ?? ?? } // mov eax, [ebp+10h], push esi, push ecx, lea esi, [eax+0C98h]  
        $pattern2 = { 4F 90 4F F8 FC E6 55 } // dec edi, nop, dec edi, clc, cld, out 55h, al  

    condition:  
        any of them  
}
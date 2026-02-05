rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 16 50 51 FF D2 5E 5D C3 }  // mov edx, [esi], push eax, push ecx, call edx, pop esi, pop ebp, ret
        $pattern1 = { 5E 5D C3 }                    // pop esi, pop ebp, ret
        $pattern2 = { 8B 45 08 56 6A 35 68 00 00 00 00 E8 74 0A 00 00 }  // mov eax, [ebp+8], push esi, push 35h, push 00000000, call 0041EB27h

    condition:
        any of them
}
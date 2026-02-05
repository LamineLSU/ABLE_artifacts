rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 4D F8 83 F8 01 74 12 }  // mov ecx,[ebp-8] cmp eax,imm32 + jb
        $pattern1 = { E8 ?? ?? ?? ?? 89 C6 }  // CALL near - push ebp; mov ebp,esp
        $pattern2 = { 83 EC 10 57 56 FF D0 }  // sub esp,10h push esi; push edi; call eax

    condition:
        any of them
}
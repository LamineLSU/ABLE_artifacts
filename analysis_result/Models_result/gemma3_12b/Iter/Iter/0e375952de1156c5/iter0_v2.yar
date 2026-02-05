rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC 5D } // mov edi, edi; push ebp; mov ebp, esp; pop edi
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 } // mov eax, dword ptr fs:[00000030h]; mov eax, dword ptr [eax+68h]; shr eax, 08h
        $pattern2 = { FF 75 08 E8 0B 00 00 00 59 FF 75 08 } // push dword ptr [ebp+08h]; call 010DA9E3h; pop ecx; push dword ptr [ebp+08h]

    condition:
        any of them
}
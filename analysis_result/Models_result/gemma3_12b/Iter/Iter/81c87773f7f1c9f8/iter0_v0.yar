rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC 5D } // mov edi, edi; push ebp; mov ebp, esp; pop ecx
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 } // mov eax, fs:[00000030h]; mov eax, dword ptr [eax+68h]; shr eax, 08h
        $pattern2 = { FF 15 AC B0 41 00 FF 15 AC B0 41 00 } // call dword ptr [0041B0ACh]; call dword ptr [0041B0ACh]

    condition:
        any of them
}
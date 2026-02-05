rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 83 F8 01 74 20 } // push ebp; mov ebp, esp; cmp eax, 01; je 00E4A9D0
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 } // mov eax, dword ptr fs:[00000030h]; mov eax, dword ptr [eax+68h]; shr eax, 08
        $pattern2 = { 59 FF 15 AC B0 41 00 } // pop ecx; call dword ptr [0041B0ACh]

    condition:
        any of them
}
rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5B 8B CE E8 25 05 00 00 }  // push 0x5B; pop edx; mov ecx, esi; call 0030667F
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }  // test eax, eax; je; mov eax, dword ptr [ebp-04h]
        $pattern2 = { 8B 85 F0 FE FF FF 8D 8D F8 FE FF FF }  // mov eax, dword ptr [ebp-00000110h]; lea ecx, dword ptr [ebp-00000108h]

    condition:
        any of them
}
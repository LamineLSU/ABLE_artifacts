rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC 83 F8 01 74 12 } // mov eax,[ebp-4] ; cmp eax, 1 ; je
        $pattern1 = { E9 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? } // jmp near rel32 ; mov eax,[esi+edi]
        $pattern2 = { 3D 00 10 00 00 0F 82 } // cmp eax, 16 ; jb

    condition:
        any of them
}
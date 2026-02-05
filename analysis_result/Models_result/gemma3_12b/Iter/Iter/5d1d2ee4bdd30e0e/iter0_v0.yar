rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 }  // mov edi, edi; push ebp; mov ebp, esp; push dword ptr [ebp+08h]
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } // push ??; pop eax; mov ebp, esp; call ??; test eax, eax
        $pattern2 = { 68 40 11 35 01 33 C9 E8 4B 17 00 00 } // push 01351140h; xor ecx, ecx; call 013544B9h

    condition:
        any of them
}
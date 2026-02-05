rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 55 8B FF 55 8B EC 83 F8 01 74 20 }  // push eax, push ebp, mov edi, edi, mov ebp, esp, cmp eax, 01h, je 00328B80h
        $pattern1 = { 8B 40 68 8B 45 08 55 8B EC 83 F8 01 74 20 } // mov eax, dword ptr [eax+68h], mov eax, dword ptr [ebp+08h], mov ebp, esp, cmp eax, 01h, je 00328B80h
        $pattern2 = { FF 15 8C C1 33 00 50 FF 15 40 C1 33 00 59 FF 15 8C C1 33 00 } // call dword ptr [0033C18Ch], push eax, call dword ptr [0033C140h], pop ecx, call dword ptr [0033C18Ch]

    condition:
        any of them
}
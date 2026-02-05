rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 6A 40 68 00 30 00 00 8B 45 08 } // push 00; push 0040; push 003000; mov eax, dword ptr [ebp+08h]
        $pattern1 = { 8B 45 FC 83 7D FC 00 75 08 6A 00 FF 15 88 7C 42 00 } // mov dword ptr [ebp-04h], eax; cmp dword ptr [ebp-04h], 00000000h; jne 00401088h; push 00000000h; call dword ptr [00427C88h]
        $pattern2 = { FF 15 B4 7D 42 00 FF 15 5C 7D 42 00 89 45 FC } // call dword ptr [00427DB4h]; call dword ptr [00427D5Ch]; mov dword ptr [ebp-04h], eax

    condition:
        any of them
}
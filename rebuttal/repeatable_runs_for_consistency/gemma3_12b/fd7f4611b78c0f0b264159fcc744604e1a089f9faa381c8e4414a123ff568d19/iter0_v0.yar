rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5B 5A 8B CE E8 25 05 00 00 85 C0 } // push 0x5b, pop edx, mov ecx, esi, call 0086667F, test eax, eax
        $pattern1 = { 8D 95 F0 FE FF FF 89 9D F0 FE FF FF 8B 85 F0 FE FF FF } // lea edx, [ebp-0x110], mov dword ptr [ebp-0x110], ebx, mov eax, dword ptr [ebp-0x110]
        $pattern2 = { FF 15 2C A1 86 00 E9 B5 FC FF FF 33 FF } // call dword ptr [0086A12C], jmp 00865E85h, xor edi, edi

    condition:
        any of them
}
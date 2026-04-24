rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5B 5A 8B CE E8 25 05 00 00 85 C0 } // push 0x5B, pop edx, mov ecx, esi, call 000B667F, test eax, eax (11 bytes)
        $pattern1 = { 8D 95 F0 FE FF FF 89 9D F0 FE FF FF 8B CE E8 74 FA FF FF } // lea edx, [ebp-0x110], mov dword ptr [ebp-0x110], ebx, mov ecx, esi, call 000B5C17 (15 bytes)
        $pattern2 = { 68 40 11 B9 00 33 C9 E8 B3 03 00 00 A1 88 85 B9 00 } // push 00B91140, xor ecx, ecx, call 00B944B9, mov eax, dword ptr [00B98588] (17 bytes)

    condition:
        any of them
}
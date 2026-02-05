rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5B 5A 8B CE E8 25 05 00 00 85 C0 } //push 0x5b; pop edx; mov ecx, esi; call 0xE1667F; test eax, eax
        $pattern1 = { 8D 95 F0 FE FF FF 89 9D F0 FE FF FF 8B CE E8 74 FA FF FF } //lea edx, [ebp-0x110]; mov dword ptr [ebp-0x110], ebx; mov ecx, esi; call 0xE15C17
        $pattern2 = { 6A 40 53 68 40 11 E1 00 33 C9 E8 B3 03 00 00 } //push 0x40; push ebx; push ebx; push 0xE11140; xor ecx, ecx; call 0xE144B9

    condition:
        any of them
}
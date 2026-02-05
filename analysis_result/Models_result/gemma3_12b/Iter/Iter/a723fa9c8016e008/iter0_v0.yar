rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5B 5A 8B CE E8 25 05 00 00 } // push 0x5B; pop edx; mov ecx, esi; call 0x667F
        $pattern1 = { 8D 95 F0 FE FF FF 89 9D F0 FE FF FF } // lea edx, [ebp-0x110]; mov dword ptr [ebp-0x110], ebx
        $pattern2 = { 68 40 11 93 00 33 C9 E8 4B 17 00 00 } // push 0x931140; xor ecx, ecx; call 0x44B9

    condition:
        any of them
}
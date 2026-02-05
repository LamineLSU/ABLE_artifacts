rule Bypass_Sample_Trace1
{
    meta:
        description = "Evasion bypass rule - Trace 1"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 6A 40 53 68 40 11 90 00 33 C9 E8 4B 17 00 00 }  //push ebx; push 0x40; push ebx; push 0x901140; xor ecx, ecx; call 009044B9h
        $pattern1 = { A1 88 85 90 00 85 C0 74 07 50 FF 15 88 A0 90 00 }  //mov eax, dword ptr [00908588h]; test eax, eax; je 009061F7h; push eax; call dword ptr [0090A088h]
        $pattern2 = { FF 15 2C A1 90 00 33 FF 8B C7 EB 03 } //call dword ptr [0090A12Ch]; xor edi, edi; jmp 00906207h

    condition:
        any of them
}
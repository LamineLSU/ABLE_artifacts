rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 }  // mov edi, edi; push ebp; mov ebp, esp; push dword ptr [ebp+08h]
        $pattern1 = { 53 6A 40 53 68 40 11 F3 00 } // pop ebx; push 0x40; pop ebx; push 0x40; push 0xF31140
        $pattern2 = { E8 C8 FF FF FF 59 FF 75 08 } // call 0040E7C3h; pop ecx; push dword ptr [ebp+08h]

    condition:
        any of them
}
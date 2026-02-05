rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC 51 51 A1 D8 EB 78 00 } // mov edi, edi; push ebp; mov ebp, esp; push ecx; push ecx; mov eax, dword ptr [0078EBD8h]
        $pattern1 = { 6A 00 50 68 FC E6 71 00 } // push 00000000h; push eax; push 0071E6FCh
        $pattern2 = { FF 15 6C 03 6E 00 85 C0 74 23 56 68 14 E7 71 00 } // call dword ptr [006E036Ch]; test eax, eax; je 006A48BAh; push esi; push 0071E714h

    condition:
        any of them
}
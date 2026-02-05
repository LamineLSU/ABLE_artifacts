rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 52 8B 16 50 50 51 51 FF D2 } // push edx/push edx/mov edx + push eax/push ecx + call edx
        $pattern1 = { 3D E4 3A C8 1B 21 40 BC 71 C6 9E FF 55 8B } // cmp eax, imm + and dword + jno + sahf + call
        $pattern2 = { 56 6A 35 6A 00 51 51 8D B0 98 0C 00 00 } // push esi/push 35h/push 00h + push ecx + lea esi + call

    condition:
        any of them
}
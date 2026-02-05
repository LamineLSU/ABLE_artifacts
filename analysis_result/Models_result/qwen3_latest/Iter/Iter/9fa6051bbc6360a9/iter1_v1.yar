rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 }  // push edx, mov edx, push eax, push ecx, call edx
        $pattern1 = { 56 56 6A 35 6A 00 51 8D B0 74 0C 00 00 }  // push esi, push esi, push 35h, push 00h, push ecx, lea esi
        $pattern2 = { 83 C4 14 52 52 8B 16 50 }  // add esp,14h, push edx, push edx, mov edx, push eax

    condition:
        any of them
}
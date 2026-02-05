rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 51 51 8B 16 50 50 51 FF D2 } // push ecx, push ecx, mov edx,[esi], push eax, push eax, push ecx, call edx
        $pattern1 = { 56 56 56 50 50 50 E8 ?? ?? ?? ?? } // push esi x3, push eax x3, call 0041AF30h
        $pattern2 = { E4 B7 35 96 33 0C A4 } // in al, B7h + xor eax, A40C3396h

    condition:
        any of them
}
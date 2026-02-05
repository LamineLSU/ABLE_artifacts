rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 16 50 51 FF D2 } // mov edx, [esi]/push eax/ push ecx/call edx
        $pattern1 = { 8D B0 98 0C 00 00 } // lea esi, [eax+0C98h]
        $pattern2 = { 93 7C E1 C2 9E 80 } // xchg eax, ebx/jl/retn (control flow alteration)

    condition:
        any of them
}
rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting RDTSC, early exit, and CPUID checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 05 86 0D ?? ?? ?? ?? 74 ?? }  // RDTSC timing check bypass
        $pattern1 = { 8B 85 9C FD FF FF 33 C0 AA }  // Early exit bypass (e.g., mov eax,dword ptr...)
        $pattern2 = { 68 68 98 41 00 ?? ?? ?? ?? ?? }  // CPUID check bypass
}

condition:
    any_of(bp0, bp1, bp2)
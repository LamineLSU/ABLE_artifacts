rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific decision sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B 4D FC }   // TEST EAX followed by specific JE
        $pattern1 = { 33 D9 5E 15 E8 BE F8 A6 8B 4D FC }  // CPUID and conditional jump
        $pattern2 = { 8B 4D FC 5F 70 C0 D3 C9 A7 B5 C7 0C }  // Conditional branch based on RDTSC

    condition:
        any of them
}
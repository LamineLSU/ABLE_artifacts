rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific conditional instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE }  // TEST EAX followed by JE/JNE
        $pattern1 = { 3D 00 10 00 00 00 0F 82 E8 4B }  // RDTSC and CPUID checks
        $pattern2 = { 8D 43 01 EA EA DD EB 01 }  // Conditional check before exit

    condition:
        (any of the patterns)
}
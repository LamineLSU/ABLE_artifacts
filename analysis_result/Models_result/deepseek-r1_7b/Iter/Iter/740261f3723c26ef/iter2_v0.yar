rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC 5F 7A 2C 03 }  // Call TEST EAX and JE
        $pattern1 = { FF 15 AC B0 41 00 FF C8 FF FF }  // Conditional call offset
        $pattern2 = { 66 69 6F 6E 74 2D 3C 75 6E 69 6F 6E 2E 30 21 }  // CPUID and RDTSC timing check

    condition:
        any of them
}
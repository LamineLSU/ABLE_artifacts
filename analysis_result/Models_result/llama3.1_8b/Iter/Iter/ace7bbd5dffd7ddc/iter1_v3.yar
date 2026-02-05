rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC 83 F8 01 74 12 }  // Concrete bytes from EVASION_CHECK
        $pattern1 = { 3D 00 10 00 00 0F 82 }  // Concrete comparison value in EXIT_DECISION
        $pattern2 = { 0F 31 C9 B8 ?? ?? ?? ?? }  // RDTSC timing and CPUID VM detection in EVASION_TECHNIQUE

    condition:
        any of them
}
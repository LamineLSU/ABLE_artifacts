rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with more targeted patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B 4D FC }  // API check pattern
        $pattern1 = { 3D 00 00 00 00 00 0F 82 E8 0D 0C 00 }  // RDTSC timing bypass
        $pattern2 = { 74 12 6A 5B 5A 8B 45 FC 01 0A 11 40 }  // Conditional check before exit

    condition:
        any of them
}
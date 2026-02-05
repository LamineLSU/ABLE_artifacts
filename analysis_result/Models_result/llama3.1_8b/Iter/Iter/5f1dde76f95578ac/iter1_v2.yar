rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 4D ?? ?? ?? ?? 83 F8 ?? ?? }  // Generic API call
        $pattern1 = { 3D ?? ?? ?? ?? ?? 0F 82 ?? ?? ?? }  // Conditional check before ExitProcess/TerminateProcess
        $pattern2 = { DC ?? ?? ?? ?? ?? 0F 31 ?? ?? }  // RDTSC timing evasion technique

    condition:
        any of them
}
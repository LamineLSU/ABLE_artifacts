rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - api_check, vm_detect, timing_check"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 56 8B EC 5E 49 A3 }   // Conditional jump or exit check
        $pattern1 = { ?? ?? 0A 00 00 00 }  // Specific OR instruction with zero values
        $pattern2 = { ?? 56 ?? 8B 45 EC 5E }  // Conditional call after setup code

    condition:
        any of them
}
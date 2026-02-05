rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - focused on key decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // TEST EAX + JE after call
        $pattern1 = { 64 A1 30 00 00 00 ?? ?? ?? }     // CPUID check before exit
        $pattern2 = { E8 6A 3E 00 00 ?? }            // VM detection bypass

    condition:
        any of them
}
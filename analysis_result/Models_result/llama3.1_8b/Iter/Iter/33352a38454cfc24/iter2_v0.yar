rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 0F 31 ?? ?? ?? ?? } // RDTSC instruction
        $pattern1 = { 8B 45 FC ?? ?? ?? ?? } // mov eax,[ebp-4] - specific stack offset
        $pattern2 = { 83 F8 01 ?? ?? ?? ?? } // cmp eax,0x1 - concrete comparison value

    condition:
        any of them
}
rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 C0 04 50 E8 ?? ?? ?? ?? }  // add eax,4; push eax; call (exit prep)
        $pattern1 = { 8B 4D FC E8 ?? ?? ?? ?? }     // mov eax, [ebp-04h]; call (check function)
        $pattern2 = { 8B 55 F8 E8 ?? ?? ?? ?? }     // mov edx, [ebp-08h]; call (another check)

    condition:
        any of them
}
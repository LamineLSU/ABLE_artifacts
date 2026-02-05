rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 56 08 50 51 FF D2 }  // Call to RtlAllocateHeap with preceding pushes
        $pattern1 = { 56 50 E8 ?? ?? ?? ?? }  // Call to 00418DB0h with preceding pushes
        $pattern2 = { 83 0D ?? ?? ?? ?? 0D }  // Sub instruction modifying memory

    condition:
        any of them
}
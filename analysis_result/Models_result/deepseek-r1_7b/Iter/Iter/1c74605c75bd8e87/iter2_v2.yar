rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specifically targeting call sequences with conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 02 0F 00 FF 75 08 }  // Conditional check before call
        $pattern1 = { 8B EC 0F 00 FF 75 08 }     // Immediate after call, bypass the next instruction
        $pattern2 = { 83 60 4D 00 FF 75 08 }    // Timing-based VM detection bypass

    condition:
        any of them
}
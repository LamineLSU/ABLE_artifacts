rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 33 FD FF FF }   // Specific test and conditional check
        $pattern1 = { E8 25 05 00 00 8B C7 }     // Call to specific function with sequential instruction
        $pattern2 = { E8 0D 0C 00 00 8B E5 }     // Another call with unique offset matching the trace
    condition:
        any of them
}
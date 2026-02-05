rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific conditional and test checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC ?? ?? ?? ?? ?? } // Test EAX and jump
        $pattern1 = { 83 F8 01 74 12 ?? ?? ?? ?? } // Conditional check before exit call
        $pattern2 = { 3D C0 10 00 00 01 00 ?? ?? ?? } // Comparison or set zero instruction

    condition:
        any of them
}
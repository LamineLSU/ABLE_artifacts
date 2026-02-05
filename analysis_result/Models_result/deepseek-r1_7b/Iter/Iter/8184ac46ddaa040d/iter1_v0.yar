rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - more specific sequences with varied addresses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? ?? } // TEST EAX with conditional jump
        $pattern1 = { 83 F8 01 74 12 ?? } // Conditional comparison and jump
        $pattern2 = { 85 C0 0F 84 74 12 ?? } // Another TEST EAX sequence

    condition:
        any of them
}
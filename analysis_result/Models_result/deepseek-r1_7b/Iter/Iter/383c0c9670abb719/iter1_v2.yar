rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? ?? ?? ?? 74 12 ?? }  // Early call followed by test and jump
        $pattern1 = { 8B 45 FC ?? ?? ?? ?? 74 1F ?? }  // Similar structure with different offset
        $pattern2 = { ?? ?? DC ?? ?? ?? ?? E8 0D 0C 00 00 }  // Timing check before exit
    condition:
        any of them
}
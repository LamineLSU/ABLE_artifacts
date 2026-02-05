rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - refined"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B ?? }  // Evasion check sequence
        $pattern1 = { 83 F8 ?? 01 74 ?? 8B 4D F8 }  // Conditional check before exit
        $pattern2 = { ?? ?? 00 00 0F 82 }  // Specific comparison pattern

    condition:
        any of them
}
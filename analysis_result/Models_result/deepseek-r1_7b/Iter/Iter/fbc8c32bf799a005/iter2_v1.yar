rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific test+je patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC } // Initial test and jump
        $pattern1 = { FF 15 AC 81 85 00 ?? ?? ?? ?? C9 F7 2D } // Conditional exit before call
        $pattern2 = { 3D 00 10 00 00 0F 82 } // Another specific test sequence

    condition:
        any of them
}
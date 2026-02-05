rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? ?? ?? ?? } // Test EAX
        $pattern1 = { E8 ?? ?? ?? ?? ?? } // CALL instruction leading to conditional check
        $pattern2 = { 3D ?? ?? ?? ?? 0F 82 ?? ?? } // Conditional comparison with jump

    condition:
        any of them
}
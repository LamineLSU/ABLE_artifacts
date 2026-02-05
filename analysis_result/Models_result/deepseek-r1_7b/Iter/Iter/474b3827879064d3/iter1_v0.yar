rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 ?? ?? ?? ?? }  // Test EAX with conditional jump
        $pattern1 = { 3D 00 10 00 00 00 0F 84 ?? ?? }  // CMP instruction followed by conditional move
        $pattern2 = { E8 4B 17 00 ?? ?? ?? 5F FF }  // Conditional exit call with varying offset

    condition:
        any of them
}
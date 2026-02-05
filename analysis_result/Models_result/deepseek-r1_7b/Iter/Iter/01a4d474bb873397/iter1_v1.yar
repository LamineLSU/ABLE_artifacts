rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - checking exit decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? ?F ?? ?C }  # Test eax and jump
        $pattern1 = { E9 B5 FC ?? ?? ?? ?E 74 12 }  # jmp leading to stack operations
        $pattern2 = { 3D 00 10 00 00 ?? ?8 ?F }  # Conditional comparison

    condition:
        any of them
}
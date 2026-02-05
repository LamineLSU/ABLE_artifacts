rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B ?? 4D ?? E8 ?? ?? ?? ?? } // CALL instruction with wildcarded address
        $pattern1 = { 83 F8 ?? 74 ?? 8B 45 ?? } // CMP instruction with wildcarded immediate value and mov instruction
        $pattern2 = { 3D ?? ?? ?? ?? 0F 82 ?? ?? ?? } // CMP instruction with wildcarded immediate value and jb instruction

    condition:
        any of them
}
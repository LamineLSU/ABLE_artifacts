rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 ?? ?? 85 C0 0F 84 ?? ?? ?? ?? } // Modified to include wildcards
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 } // Specific bytes for conditional check before exit
        $pattern2 = { E8 E0 A2 FF FF 85 C0 74 0E } // Specific bytes for call instruction

    condition:
        any of them
}
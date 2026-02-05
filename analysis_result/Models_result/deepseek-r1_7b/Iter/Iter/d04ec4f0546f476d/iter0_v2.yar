rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 1A ?? ?? ?? ?? } // Example pattern for 'je' instruction
        $pattern1 = { 75 8E 9C 01 ?? ?? ?? ?? ?? } // Example pattern for conditional jump with displacement
        $pattern2 = { E8 ?? ?? ?? ?? 8B ?? } // Example pattern for call instruction with context
    condition:
        any of them
}
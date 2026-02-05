rule Bypass_Sample {
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 8A 5D FF C3 ?? ?? ?? ?? ?? ?? B4 5E } // Focuses on a specific call and surrounding context
        $pattern1 = { 6A 5F 7A ?? ?? ?? ?? 8B F2 F8 } // Targets another section with similar instruction flow
        $pattern2 = { FF C0 3C ?? ?? ?? ?? ?? ?? ?? ?? } // Captures a distinct pattern from the trace

    condition:
        any_of them
}
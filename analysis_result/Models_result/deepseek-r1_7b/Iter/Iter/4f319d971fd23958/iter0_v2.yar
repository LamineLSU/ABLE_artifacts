rule EvasionBypass {
    meta:
        description = "Detect evasion bypass by skipping critical instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? } // Skip call instruction
        $pattern1 = { ?? ?? ?? ?? 51 ?? ?? ?? ?? ?? 51 ?? } // Skip push ecx
        $pattern2 = { ?? ?? ?? 83 C4 14 ?? ?? ?? ?? ?? ?? } // Skip esp addition

    condition:
        any of them
}
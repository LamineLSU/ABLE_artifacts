rule Bypass_Evasion_Patterns {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? 45 ?? }  // Combines stack operations and call
        $pattern1 = { 6D 79 73 7F 0F 7E FF ?? ?? ?? ?? F5 FF 2D 7E 0F ?? }  // Includes different displacements
        $pattern2 = { E8 45 BD D1 B9 FF 45 ?? ?? F5 FF 0F F6 ?? ?? }  // Targets early code path with wildcards

    condition:
        any_of them
}
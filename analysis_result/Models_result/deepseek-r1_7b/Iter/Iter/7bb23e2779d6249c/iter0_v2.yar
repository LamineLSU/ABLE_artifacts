rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection using specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } // Skipping a specific call sequence
        $pattern1 = { E8 45 5A 8B CE E8 8F F7 FF FF FF F1 C3 } // Bypassing conditional jump operations
        $pattern2 = { EA 05 8B EC E8 C8 FF FF FF F1 A3 } // Skipping a TEST instruction before exit call

    condition:
        any of them
}
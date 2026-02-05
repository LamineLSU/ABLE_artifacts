rule Bypass_Sample_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 55 8B EC FF 75 08 E8 C8 FF FF }
        $pattern1 = { 74 07 83 C4 } // Additional bytes as needed
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? } // Include wildcards for unknown offsets

    condition:
        any of them
}
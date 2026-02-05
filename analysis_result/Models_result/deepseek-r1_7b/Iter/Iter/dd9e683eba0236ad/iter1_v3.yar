rule Bypass_Sample_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC 5E 45 ?? ?? ?? ?? ?? ?? }  // Example for Push and Pop Operations
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 5C ?? ?? ?? }  // Example for Conditional Jumps and Memory Accesses
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? ?? }  // Another Unique Instruction Sequence

    condition:
        any of them
}
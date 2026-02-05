rule Bypass_Evasion {
    meta:
        description = "Evasion bypass patterns targeting specific instructions to avoid detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? 85 C0 ?? F5 28 }  // Around the call in TRACE //1
        $pattern1 = { E8 ?? ?? ?? ?? 8B 45 ?? 83 C4 ?? 85 C0 ?? ?? }  // Surrounding instructions with wildcards
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }  // From the second trace with mov instruction and wildcards

    condition:
        any of them
}
rule Bypass_Evasion {
    meta:
        description = "Evasion bypass for exit process"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }  // Includes context before the call
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }  // Focuses on the call and surrounding mov/push
        $pattern2 = { E8 7C 4F 7F 83 C4 14 5E 5D C3 }       // Direct call sequence with wildcards for unknown bytes
}

    condition:
        any of them
}
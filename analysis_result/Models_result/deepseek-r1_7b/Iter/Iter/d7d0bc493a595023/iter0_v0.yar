rule Bypass_Sample {
    meta:
        description = "Evasion bypass using different call instruction displacements"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 C0 8B EC FF 75 08 E8 C1 FF FF }     // First pattern from a call instruction
        $pattern1 = { 6A ?? 5A 8B CE E8 FF 15 68 F3 8D 00 }   // Second unique pattern with displacement
        $pattern2 = { E8 C1 FF FF FF FF FF ?? FF 75 08 } // Third pattern including wildcards

    condition:
        any()
}
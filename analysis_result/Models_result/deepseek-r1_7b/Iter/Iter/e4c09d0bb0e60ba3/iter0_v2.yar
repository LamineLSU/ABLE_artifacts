rule Bypass_Pattern_3 {
    meta:
        description = "Third bypass mechanism for ExitProcess"
        cape_options = "bp0=$pattern6+0,action0=skip,bp1=$pattern7+0,action1=skip,bp2=$pattern8+0,action2=skip,count=0"
    strings:
        $pattern6 = { 8B CE 0F 84 FF C1 5A E8 25 05 00 00 00 }   // Core operations
        $pattern7 = { 6A 5B 00 00 40 0E 7F 08 FF 15 AC B0 41 }   // Variable offsets
        $pattern8 = { E8 C8 FF FF FF 00 00 00 00 00 00 00 00 00 00 } // Immediate arguments
    condition:
        any_of_them
}
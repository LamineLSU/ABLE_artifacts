rule EvasionBypass {
    meta:
        description = "Bypasses sandbox/VM evasion through call and stack manipulation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 41 A6 48 52 8B 16 FF D2 5E 5D C3 }  // Skipping 'call' instruction
        $pattern1 = { 00 41 A6 C8 FF D0 8B 06 E8 44 }       // Bypassing a call to 'eax'
        $pattern2 = { 6A 35 6A 00 51 8D B0 7C 0C 8B 55 0C }   // Manipulating stack operations
    condition:
        any of them
}
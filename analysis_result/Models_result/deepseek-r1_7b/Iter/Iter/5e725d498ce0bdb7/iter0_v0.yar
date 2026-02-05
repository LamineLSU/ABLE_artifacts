rule EvasionBypass {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 56 8B EC 4D FE F9 7E ?? }   // Pattern matching call instructions
        $pattern1 = { E8 8B 45 0C C3 40 8F 2A 6A 5E }  // Loop with stack manipulation
        $pattern2 = { 7C C0 59 AD ?? CC 8B ED 8D 5E }   // Conditional jumps bypassed

    condition:
        any of them
}
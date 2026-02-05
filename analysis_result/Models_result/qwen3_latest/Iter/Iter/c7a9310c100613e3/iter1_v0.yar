rule EvasionCheckPatterns
{
    meta:
        description = "Detects evasion checks and related control flow before ExitProcess"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Security Researcher"
        date = "2023-10-15"

    strings:
        $pattern0 = { 66 83 F8 01 75 20 }  // cmp ax, 0x01 + jne 0x20
        $pattern1 = { 66 83 F8 01 75 0D }  // cmp ax, 0x01 + jne 0x0D
        $pattern2 = { E8 ?? ?? ?? ?? 6A 27 }  // call (offset) + push 0x27

    condition:
        any of them
}
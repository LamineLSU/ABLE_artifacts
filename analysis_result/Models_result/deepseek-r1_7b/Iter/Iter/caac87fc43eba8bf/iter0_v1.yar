rule Bypass_Sample {
    meta:
        description = "Evasion bypass through multiple call paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 55 8B EC FF 75 08 E8 C4 } // push ebp, mov esp, push dword ptr, call dword ptr
        $pattern1 = { 59 FF 75 08 E8 C4 }       // pop ecx, push dword ptr, call dword ptr
        $pattern2 = { FF 7F 15 AC B0 41 }   // displacement jump to address

    condition:
        any() // Matches if any pattern is detected
}
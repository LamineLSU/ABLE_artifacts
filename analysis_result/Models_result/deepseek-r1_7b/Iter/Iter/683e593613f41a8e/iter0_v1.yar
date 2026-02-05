rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 33 CD E8 25 05 }  // TEST EAX and JZ/JE with address
        $pattern1 = { 6A 5B 03 C3 8B CE E8 74 FA }    // Unwanted stack push followed by function call bypass
        $pattern2 = { 8B EC FF 75 08 00 00 01 04 FF 75 }  // Conditional jump after function calls
}

    condition:
        any of them
}
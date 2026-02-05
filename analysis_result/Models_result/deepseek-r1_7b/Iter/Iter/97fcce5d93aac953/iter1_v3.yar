rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - checked for specific conditional jumps after calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 59 FF 75 08 8B 45 FC } // Pop ecx and check EAX condition
        $pattern1 = { 3D F8 01 74 12 8B 4D F8 } // Specific cmp and jump sequence
        $pattern2 = { 8B EC ED ED 55 EB 8B EC EB FF 75 08 DD EB 08 E8 C8 FF FF FF CA DD 00 40 94 2E } // Comprehensive check before exit
}

condition:
    (any of $pattern0, $pattern1, $pattern2)
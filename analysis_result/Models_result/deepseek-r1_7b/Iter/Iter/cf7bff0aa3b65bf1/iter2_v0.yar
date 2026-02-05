rule Bypass_Sample {
    meta:
        description = "Evasion bypass targeting three distinct instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FF FF FE ?? FF 75 }  // Represents a call with displacement and following push instruction
        $pattern1 = { 55 FF 75 08 8B EC 59 FF ?? }  // Includes push ebp, mov ebp, pop ecx, and next instruction
        $pattern2 = { FF 75 08 83 C4 ?? ?? }       // Represents a different instruction sequence with wildcards

    condition:
        any of them
}
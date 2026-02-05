rule Bypass_Sample {
    meta:
        description = "Evasion bypass using stack manipulation and address displacement"
        cape_options = "bp0=$pattern0,action0=skip,bp1=$pattern1,action1=skip,bp2=$pattern2,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 F5 08 E8 C8 FF FF }  // Specific call instruction with surrounding context
        $pattern1 = { FF 15 64 10 41 00 }       // Another specific instruction from the trace
        $pattern2 = { 0F 8C FF FF FF FF }         // Additional distinct pattern

    condition:
        any_of them
}
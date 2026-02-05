rule Bypass_Sample {
    meta:
        description: "Evasion bypass analysis"
        cape_options: "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 7E ?? ?? ?? }  // Example with displacement and two more instructions
        $pattern1 = { FF 15 B8 30 FB 00 }  // Example of a call instruction
        $pattern2 = { FF 15 BC 30 FB 00 }  // Another example of a call instruction

    condition:
        any of them
}
rule SpecificPatterns
{
    meta:
        description = "Detects specific patterns from the provided disassembled code."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"

    strings:
        $a = { E8 F7 25 00 00 83 F8 01 74 20 }  // Check function and conditional jump
        $b = { A8 01 75 10 }               // Test and jump logic
        $c = { FF 15 A0 F1 42 00 }            // ExitProcess call

    condition:
        all of ($a, $b, $c)
}
rule ExampleRule {
    meta:
        description = "Matches specific patterns in a binary file"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 8B 55 08 FF D2 5E 5D C3 }  // Call to RtlAllocateHeap with surrounding instructions
        $b = { E8 ?? ?? ?? ?? }          // Generic call instruction (offsets wildcardized)
        $c = { 00 56 50 }                // Add byte instruction with offset
    condition:
        all of them
}
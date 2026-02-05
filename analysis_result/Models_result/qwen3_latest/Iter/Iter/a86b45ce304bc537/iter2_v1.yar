rule EvasionDetection
{
    meta:
        description = "Detects evasion techniques in a sample by matching specific code sequences."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 50 51 FF D2 5E 5D C3 } // Call to RtlAllocateHeap with register manipulation
        $b = { E8 44 09 00 00 8B 45 FC } // Hardcoded call to 0041A950h followed by register load
        $c = { 1C CE A3 D6 DB E4 B1 } // Unique sbb/mov sequence for obfuscated data
    condition:
        all of them
}
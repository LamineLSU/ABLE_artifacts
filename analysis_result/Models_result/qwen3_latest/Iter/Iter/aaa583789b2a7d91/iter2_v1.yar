rule Bypass_Sample_Evolved
{
    meta:
        description = "Detects a specific bypass pattern in the sample code"
        cape_options = "all_patterns"

    strings:
        $a = { E8 6E FF FF FF 6A 00 }  // Call followed by push
        $b = { E8 2D 01 00 00 CC }     // Call to ExitProcess followed by int3
        $c = { 6A 00 E8 2D 01 00 00 } // Push followed by call to ExitProcess

    condition:
        any of them
}
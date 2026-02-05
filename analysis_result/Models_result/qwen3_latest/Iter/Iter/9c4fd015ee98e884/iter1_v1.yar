rule ExitDetectionPatterns
{
    meta:
        description = "Detects common exit or cleanup patterns in binaries"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        confidence = 70

    strings:
        $a = { E8 C8 FF FF FF 59 } // Call to ___crtCorExitProcess
        $b = { 55 8B EC FF 75 08 }     // Stack frame setup
        $c = { 59 FF 15 AC B0 41 00 } // Call to ExitProcess

    condition:
        any of them
}
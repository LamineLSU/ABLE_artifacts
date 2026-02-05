rule ExitProcessPattern
{
    meta:
        description = "Matches a specific code sequence associated with a controlled exit process."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        confidence = 50

    strings:
        $a = { 55 8B EC FF 75 08 E8 C1 FF FF FF }  // Setup and call to ___crtCorExitProcess
        $b = { FF 15 68 F3 20 00 }                // Call to ExitProcess
        $c = { FF 75 08 FF 15 68 F3 20 00 }         // Push and call to ExitProcess

    condition:
        any of ($a, $b, $c)
}
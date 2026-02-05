rule Malware_Exit_Point
{
    meta:
        description = "Detects code that calls ExitProcess or CRT exit functions"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        confidence = 4

    strings:
        $a = { 55 8B EC FF 75 08 }           // Function prologue
        $b = { FF 75 08 E8 C8 FF FF FF }    // Call to __crtCorExitProcess
        $c = { 59 FF 75 08 FF 15 AC B0 41 00 } // Call to ExitProcess

    condition:
        any of ($a, $b, $c)
}
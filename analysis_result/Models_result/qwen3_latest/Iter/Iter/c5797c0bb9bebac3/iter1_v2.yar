rule ExitProcessCallSequence
{
    meta:
        description = "Detects the call sequence to ExitProcess and related CRT functions"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
    strings:
        $a = { FF 75 08 E8 ?? ?? ?? ?? } // Push + call to ___crtCorExitProcess
        $b = { FF 15 AC B0 41 00 }        // Call to ExitProcess
        $c = { FF 75 08 E8 C8 FF FF FF } // Exact call to ___crtCorExitProcess
    condition:
        all of ($a, $b, $c)
}
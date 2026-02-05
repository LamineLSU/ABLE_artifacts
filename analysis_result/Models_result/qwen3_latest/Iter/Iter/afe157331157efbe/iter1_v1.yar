rule ExitCheckPatterns
{
    meta:
        description = "Detects evasion logic via exit-related API calls"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Security Analyst"

    strings:
        $a = { FF 75 08 E8 C8 FF FF FF } // Push + call to ___crtCorExitProcess (check)
        $b = { FF 15 AC B0 41 00 }        // Call to ExitProcess (termination)
        $c = { 55 8B EC }                 // Stack frame setup (common in exit routines)

    condition:
        all of ($a, $b, $c)
}
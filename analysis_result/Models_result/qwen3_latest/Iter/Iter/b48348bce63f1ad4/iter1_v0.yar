rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC FF 75 08 }  // Function prologue + push [ebp+08h] (ASCII '\')
        $pattern1 = { E8 C1 FF FF FF }       // Call to ___crtCorExitProcess (first exit check)
        $pattern2 = { FF 15 5C C2 4C 00 }   // Call to ExitProcess (final termination)

    condition:
        any of them
}
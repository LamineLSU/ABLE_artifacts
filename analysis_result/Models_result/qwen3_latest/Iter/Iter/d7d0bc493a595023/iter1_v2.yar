rule MaliciousExecution
{
    meta:
        description = "Detects malicious execution flow involving evasion checks and exit actions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
    strings:
        $pattern0 = { E8 C1 ?? ?? ?? } // Call to ___crtCorExitProcess (evasion check)
        $pattern1 = { FF 15 68 F3 20 00 } // Call to ExitProcess (exit action)
        $pattern2 = { 55 8B EC FF 75 08 } // Function prologue (stack setup)
    condition:
        $pattern0 or $pattern1 or $pattern2
}
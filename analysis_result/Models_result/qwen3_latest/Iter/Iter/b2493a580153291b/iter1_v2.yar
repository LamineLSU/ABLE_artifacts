rule EvasionExitDecision
{
    meta:
        description = "Detects code that performs an evasion check and then terminates based on the result."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"

    strings:
        $a = { E8 ?? ?? ?? ?? 83 F8 01 74 20 } // Evasion check
        $b = { A8 01 75 10 } // Second evasion check
        $c = { FF 15 A0 50 F4 00 } // Exit decision (TerminateProcess)

    condition:
        all of ($a, $b, $c)
}
rule MaliciousProcessTermination
{
    meta:
        description = "Detects process termination logic or attempt to terminate itself."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        confidence = 80

    strings:
        $a = { E8 F7 25 00 00 83 F8 01 74 20 } // Check logic before termination
        $b = { A8 01 75 10 }              // Conditional jump based on bit test
        $c = { FF 15 40 F1 42 00 }          // Call to TerminateProcess

    condition:
        any of ($a, $b, $c)
}
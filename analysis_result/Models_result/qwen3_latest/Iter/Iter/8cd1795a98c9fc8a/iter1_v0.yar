rule ProcessExitCheck
{
    meta:
        description = "Detects conditional checks and exit logic in a process"
        cape_options = "bp0=$check+0,action0=skip,bp1=$terminate+0,action1=skip,bp2=$exit+0,action2=skip,count=0"
    strings:
        $check = { E8 ?? ?? ?? ?? 83 F8 01 74 ?? }  // Conditional check
        $terminate = { FF 15 40 F1 42 00 }            // Call to TerminateProcess
        $exit = { FF 15 A0 F1 42 00 }                // Call to ExitProcess
    condition:
        all of them
}
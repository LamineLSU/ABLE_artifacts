rule bypass_exit_process {
    meta:
        description = "Bypasses the call to ExitProcess by targeting critical function calls and control flow instructions."
        cape_options = "bp0=$call1+0,action0=skip,bp1=$call2+0,action1=skip,bp2=$call3+0,action2=skip,count=0"
        author = "Your Name"
        date = "2023-10-10"

    strings:
        // Pattern 1: Call to 0041EB27 preceded by PUSH EAX
        $call1 = { 50 E8 ?? ?? ?? ?? }

        // Pattern 2: PUSH EDX followed by CALL EAX (ExitProcess)
        $call2 = { 83 C4 14 52 FF D0 }

        // Pattern 3: Call to 0041EB27 with subsequent instructions leading to ExitProcess
        $call3 = { E8 ?? ?? ?? ?? 8B 06 83 C4 14 52 }

    condition:
        any of ($call1, $call2, $call3)
}
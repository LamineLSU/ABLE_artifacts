rule MaliciousCodeDetection
{
    meta:
        description = "Detects malicious code with evasion checks and forced exit."
        cape_options = "bp0=$in_check+0,action0=skip,bp1=$evasion_call+0,action1=skip,bp2=$forced_exit+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2023-10-25"

    strings:
        // Bypass 1: IN instruction checking for debugger
        $in_check = { 83 C4 14 E4 ?? 52 FF E0 }

        // Bypass 2: Call to potential evasion function
        $evasion_call = { 56 57 55 8B D6 E8 ?? ?? ?? ?? }

        // Bypass 3: Forced exit to ExitProcess
        $forced_exit = { 83 C4 14 52 FF E0 }

    condition:
        all of (
            $in_check or
            $evasion_call or
            $forced_exit
        )
}
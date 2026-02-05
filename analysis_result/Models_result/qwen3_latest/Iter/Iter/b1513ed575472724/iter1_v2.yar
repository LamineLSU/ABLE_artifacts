rule TargetedCodeFlow
{
    meta:
        description = "Detects a code sequence involving control flow checks and exit calls"
        cape_options = "bp0=$check_flow+0,action0=skip,bp1=$terminate_call+0,action1=skip,bp2=$exit_call+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        // Pattern 1: Check function call + comparison + conditional jump
        $check_flow = { E8 F7 25 00 00 83 F8 01 74 20 }

        // Pattern 2: Call to TerminateProcess
        $terminate_call = { 50 FF 15 40 F1 42 00 }

        // Pattern 3: Call to ExitProcess
        $exit_call = { 50 FF 15 A0 F1 42 00 }

    condition:
        all of (
            $check_flow,
            $terminate_call,
            $exit_call
        )
}
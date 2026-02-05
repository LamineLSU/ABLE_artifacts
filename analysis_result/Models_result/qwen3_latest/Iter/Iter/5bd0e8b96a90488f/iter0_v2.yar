rule MaliciousTerminationLogic
{
    meta:
        description = "Detects code flow leading to early termination (sandbox detection)"
        cape_options = "bp0=$call_exitproc+0,action0=skip,bp1=$call_terminate+0,action1=skip,bp2=$call_getcurrent+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2025-04-05"
        threat_level = "high"

    strings:
        // Pattern 0: Pop ECX + Push [ebp+08h] + Call ExitProcess
        $call_exitproc = { 59 FF 75 08 FF 15 ?? ?? ?? ?? }

        // Pattern 1: Push EAX + Call TerminateProcess
        $call_terminate = { 50 FF 15 ?? ?? ?? ?? }

        // Pattern 2: Push [ebp+08h] + Call GetCurrentProcess
        $call_getcurrent = { FF 75 08 FF 15 ?? ?? ?? ?? }

    condition:
        all of them
}
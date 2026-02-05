rule Malware_Exit_Through_ExitProcess
{
    meta:
        description = "Detects malware attempting to exit via ExitProcess, which may be blocked by sandbox detection."
        cape_options = "bp0=$push_call+0,action0=skip,bp1=$call_exitprocess+0,action1=skip,bp2=$pop_push_call+0,action2=skip,count=0"
        author = "YourName"
        date = "2025-04-01"

    strings:
        // Pattern 1: Push [ebp+08h] followed by call to ExitProcess
        $push_call = { FF 75 08 FF 15 ?? ?? ?? ?? }

        // Pattern 2: Direct call to ExitProcess (displacement replaced with ??)
        $call_exitprocess = { FF 15 ?? ?? ?? ?? }

        // Pattern 3: Pop ecx, Push [ebp+08h], Call to ExitProcess
        $pop_push_call = { 59 FF 75 08 FF 15 ?? ?? ?? ?? }

    condition:
        (all of ($push_call, $call_exitprocess, $pop_push_call)) or
        (any of ($push_call, $call_exitprocess, $pop_push_call))
}
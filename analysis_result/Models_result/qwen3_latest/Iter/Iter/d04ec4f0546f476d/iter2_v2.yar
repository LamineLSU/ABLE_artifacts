rule Specific_API_Calls
{
    meta:
        description = "Targeted API calls from the observed sample"
        cape_options = "bp0=$call_getcurrentprocess+0,action0=skip,bp1=$call_terminateprocess+0,action1=skip,bp2=$call_exitprocess+0,action2=skip,count=0"
        confidence = 70

    strings:
        $call_getcurrentprocess = { FF 15 10 61 3A 00 }  // Call to GetCurrentProcess
        $call_terminateprocess = { FF 15 14 61 3A 00 }  // Call to TerminateProcess
        $call_exitprocess = { FF 15 48 61 3A 00 }        // Call to ExitProcess

    condition:
        all of ($call_getcurrentprocess, $call_terminateprocess, $call_exitprocess)
}
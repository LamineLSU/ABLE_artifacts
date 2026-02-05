rule Bypass_Sample_Evolved
{
    meta:
        description = "Detects evasion check and exit logic based on specific API calls and register manipulation"
        cape_options = "bp0=$call_crt_exit+0,action0=skip,bp1=$push_ebp_08+0,action1=skip,bp2=$call_exitproc+0,action2=skip,count=0"
        author = "ThreatIntel"
        date = "2023-10-15"

    strings:
        $call_crt_exit = { E8 C8 ?? ?? ?? } // Call to __crtCorExitProcess
        $push_ebp_08 = { FF 75 08 } // Push [ebp+08h] (common in stack manipulation)
        $call_exitproc = { FF 15 AC B0 41 00 } // Call to ExitProcess (Windows API)

    condition:
        all of ($call_crt_exit, $push_ebp_08, $call_exitproc)
}
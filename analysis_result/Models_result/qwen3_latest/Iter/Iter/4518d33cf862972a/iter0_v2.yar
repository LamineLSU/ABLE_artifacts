rule ExitProcess_Call
{
    meta:
        description = "Detects the call to ExitProcess used for sandbox evasion."
        cape_options = "bp0=$call_exitprocess+0,action0=skip,bp1=$call_exitprocess_2+0,action1=skip,count=0"
        author = "Your Name"
        date = "2023-10-05"

    strings:
        $call_exitprocess = { FF 15 ?? ?? ?? ?? } // CALL [address]
        $call_exitprocess_2 = { FF 15 ?? ?? ?? ?? } // CALL [address]

    condition:
        (uint16($call_exitprocess) == 0x15FF) or (uint16($call_exitprocess_2) == 0x15FF)
}
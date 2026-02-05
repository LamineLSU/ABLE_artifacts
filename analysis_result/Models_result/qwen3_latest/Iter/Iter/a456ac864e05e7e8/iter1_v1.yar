rule ExitProcessDetection
{
    meta:
        description = "Detects the call to ExitProcess and related instructions in a process"
        cape_options = "bp0=$call_crt_cor+0,action0=skip,bp1=$call_exit_process+0,action1=skip,bp2=$push_before_call+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-01"

    strings:
        $call_crt_cor = { E8 C8 FF FF FF }
        $call_exit_process = { FF 15 AC B0 41 00 }
        $push_before_call = { FF 75 08 }

    condition:
        all of them
}
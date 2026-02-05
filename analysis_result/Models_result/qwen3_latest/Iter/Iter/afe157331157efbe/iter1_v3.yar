rule ProcessTerminationCheck
{
    meta:
        description = "Detects a process termination check pattern, possibly used for evasion or termination control."
        cape_options = "bp0=$call_to_crt_cor_exit+0,action0=skip,bp1=$pop_ecx+0,action1=skip,bp2=$push_ebp_plus_08+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2025-03-15"

    strings:
        $call_to_crt_cor_exit = { E8 C8 FF FF FF }
        $pop_ecx = { 59 }
        $push_ebp_plus_08 = { FF 75 08 }

    condition:
        all of (
            $call_to_crt_cor_exit,
            $pop_ecx,
            $push_ebp_plus_08
        )
}
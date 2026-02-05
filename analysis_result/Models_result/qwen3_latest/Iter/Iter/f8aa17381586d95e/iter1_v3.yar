rule Evasion_CallEAX
{
    meta:
        description = "Detects a potential evasion mechanism using CALL EAX to invoke ExitProcess or similar functions"
        cape_options = "bp0=$call_eax_seq+0,action0=skip,bp1=$call_eax+0,action1=skip,bp2=$post_call_seq+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        $call_eax_seq = { 52 FF D0 5E }
        $call_eax = { FF D0 ?? ?? ?? ?? }
        $post_call_seq = { 5E 5F 5D }

    condition:
        any of them
}
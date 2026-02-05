rule ExitProcess_Bypass
{
    meta:
        description = "Detects a potential bypass of the ExitProcess call by identifying the instruction sequence leading to it."
        cape_options = "bp0=$call_seq+0,action0=skip,count=0"
        author = "Your Name"
        date = "2025-03-25"

    strings:
        $call_seq = { 53 E8 ?? ?? ?? ?? }  // push ebx followed by call with displacement

    condition:
        $call_seq
}
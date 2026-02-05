rule ExitProcessCall
{
    meta:
        description = "Detects a call to ExitProcess, commonly used to terminate a process."
        cape_options = "bp0=$call_seq+0,action0=skip,count=0"
        author = "Your Name"
        date = "2025-03-15"
        confidence = "high"

    strings:
        $call_seq = { FF 75 08 FF 15 ?? ?? ?? ?? }

    condition:
        $call_seq
}
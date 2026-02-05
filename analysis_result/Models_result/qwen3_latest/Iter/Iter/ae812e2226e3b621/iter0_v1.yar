rule ExitProcessCall
{
    meta:
        description = "Detects a call to ExitProcess, commonly used in sandbox escape or malicious payloads."
        cape_options = "bp0=$call_to_exitprocess+0,action0=skip,count=0"
        author = "Security Analyst"
        date = "2025-04-15"

    strings:
        $call_to_exitprocess = { 53 E8 ?? ?? ?? ?? }  // push ebx followed by call to ExitProcess

    condition:
        $call_to_exitprocess
}
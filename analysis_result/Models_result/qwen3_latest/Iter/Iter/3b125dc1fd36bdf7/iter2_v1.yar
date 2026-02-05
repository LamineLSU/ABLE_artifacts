rule GetCommandLineA_Call
{
    meta:
        description = "Call to GetCommandLineA API"
        cape_options = "bp0=$call_getcmd+0,action0=skip,count=0"
        author = "Your Name"
    strings:
        $call_getcmd = { FF 15 BC A0 41 00 }
    condition:
        $call_getcmd
}
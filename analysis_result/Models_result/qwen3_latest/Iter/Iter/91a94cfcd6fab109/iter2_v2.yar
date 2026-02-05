rule ExitProcess_Call {
    meta:
        description = "Call to ExitProcess (KERNEL32)"
        cape_options = "bp0=$call_exitprocess+0,action0=skip,count=0"
    strings:
        $call_exitprocess = { FF 15 AC B0 41 00 }
    condition:
        $call_exitprocess
}
rule ExitProcess_Call
{
    meta:
        description = "Detects a direct call to ExitProcess"
        cape_options = "bp0=$call+0,action0=skip,count=0"
        author = "Your Name"
    strings:
        $call = { FF 15 AC B0 41 00 }
    condition:
        $call
}
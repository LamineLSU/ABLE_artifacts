rule ExitProcess_Calls
{
    meta:
        description = "Detects calls to ExitProcess and related functions"
        cape_options = "bp0=$call1+0,action0=skip,bp1=$call2+0,action1=skip,bp2=$setup+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2025-04-01"

    strings:
        $call1 = { FF 75 08 E8 ?? ?? ?? ?? 59 }
        $call2 = { FF 75 08 FF 15 ?? ?? ?? ?? }
        $setup = { 55 8B EC FF 75 08 }

    condition:
        all of them
}
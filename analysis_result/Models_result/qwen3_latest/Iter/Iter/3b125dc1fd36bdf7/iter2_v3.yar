rule Win32_API_Call_Sequence
{
    meta:
        description = "Detects a sequence of API calls to GetCommandLineA, GetStartupInfoA, and ExitProcess."
        cape_options = "bp0=$call_getcommandlinea+0,action0=skip,bp1=$call_getstartupinfoa+0,action1=skip,bp2=$call_exitprocess+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-03-15"

    strings:
        $call_getcommandlinea = { FF 15 BC A0 41 00 }
        $call_getstartupinfoa = { FF 15 C0 A0 41 00 }
        $call_exitprocess = { FF 15 28 A2 41 00 }

    condition:
        all of them
}
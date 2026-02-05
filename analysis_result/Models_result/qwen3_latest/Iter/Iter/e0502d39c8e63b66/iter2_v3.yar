rule ProcessInitializationCheck
{
    meta:
        description = "Detects a process initialization sequence leading to ExitProcess"
        cape_options = "bp0=$getcmdline+0,action0=skip,bp1=$getstartup+0,action1=skip,bp2=$exitprocess+0,action2=skip,count=0"
        author = "Your Name"

    strings:
        $getcmdline = { FF 15 BC A0 41 00 }
        $getstartup = { FF 15 C0 A0 41 00 }
        $exitprocess = { FF 15 28 A2 41 00 }

    condition:
        all of ($getcmdline, $getstartup, $exitprocess)
}
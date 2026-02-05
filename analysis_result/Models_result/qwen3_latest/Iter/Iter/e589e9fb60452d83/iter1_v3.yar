rule MalwareExitCheck
{
    meta:
        description = "Detects exit logic involving conditional checks and API calls."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
        date = "2023-10-25"

    strings:
        $a = { E8 36 34 01 00 83 F8 01 74 20 }  // Conditional check
        $b = { FF 15 C0 A0 46 00 50 FF 15 20 A2 46 00 }  // GetCurrentProcess -> TerminateProcess
        $c = { FF 75 08 FF 15 04 A2 46 00 }  // ExitProcess call

    condition:
        all of ($a, $b, $c)
}
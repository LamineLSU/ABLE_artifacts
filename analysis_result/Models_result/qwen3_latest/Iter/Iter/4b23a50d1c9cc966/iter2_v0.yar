rule ExitDecisionLogic
{
    meta:
        description = "Detects code that leads to termination via ExitProcess or TerminateProcess"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "YourName"
        date = "2025-04-05"

    strings:
        $a = { E8 F7 25 00 00 83 F8 01 74 20 }
        $b = { FF 15 3C F1 42 00 50 FF 15 40 F1 42 00 }
        $c = { FF 75 08 FF 15 A0 F1 42 00 }

    condition:
        any of them
}
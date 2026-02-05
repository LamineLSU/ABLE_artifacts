rule EvasionExitProcess
{
    meta:
        description = "Detects evasion mechanism via call to ExitProcess"
        cape_options = "bp0=$p1+0,action0=skip,bp1=$p2+0,action1=skip,bp2=$p3+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        $p1 = { 52 FF D0 5E 5D C3 }
        $p2 = { 83 C4 ?? 52 FF D0 }
        $p3 = { FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}
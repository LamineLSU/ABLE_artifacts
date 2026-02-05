rule ExitProcess_Call_Context
{
    meta:
        description = "Detects calls to ExitProcess with contextual instructions"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Security Researcher"
        date = "2023-10-15"

    strings:
        $a = { FF 75 08 E8 ?? ?? ?? ?? 59 }
        $b = { E8 ?? ?? ?? ?? 59 FF 75 08 }
        $c = { FF 75 08 FF 15 ?? ?? ?? ?? }

    condition:
        any of ($a, $b, $c)
}
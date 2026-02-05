rule ExitProcessSequence
{
    meta:
        description = "Matches a sequence of instructions leading to an ExitProcess call."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"
        confidence = 85

    strings:
        $a = { E8 C8 FF FF FF }
        $b = { FF 75 08 }
        $c = { FF 15 AC B0 41 00 }

    condition:
        all of ($a, $b, $c)
}
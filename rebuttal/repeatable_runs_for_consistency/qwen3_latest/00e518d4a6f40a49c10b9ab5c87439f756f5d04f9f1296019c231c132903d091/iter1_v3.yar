rule CallPatterns
{
    meta:
        description = "Detects specific call patterns in a binary"
        cape_options = "bp0=$call1+0,action0=skip,bp1=$call2+0,action1=skip,bp2=$call3+0,action2=skip,count=0"
        author = "Your Name"
        date = "2023-10-05"

    strings:
        $call1 = { E8 25 05 00 00 85 C0 74 12 }
        $call2 = { E8 74 FA FF FF 85 C0 0F 84 33 FD FF FF }
        $call3 = { FF 15 2C A1 AC 00 }

    condition:
        all of them
}
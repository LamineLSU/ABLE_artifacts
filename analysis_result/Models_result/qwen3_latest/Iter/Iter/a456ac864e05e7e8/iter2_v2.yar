rule SampleBypass
{
    meta:
        author = "RedTeam"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        date = "2023-10-05"
        description = "Bypasses checks by hooking CRT exit and stack setup"

    strings:
        $a = { E8 C8 FF FF FF } // CRT exit call
        $b = { FF 15 AC B0 41 00 } // ExitProcess call
        $c = { 8B FF 55 8B EC } // Stack setup

    condition:
        all of ($a, $b, $c)
}
rule ExitProcess_Detection
{
    meta:
        description = "Detects the call to ExitProcess or related exit functions."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-15"
        confidence = 75

    strings:
        $a = { FF 75 08 E8 C8 ?? ?? ?? }
        $b = { FF 15 AC B0 41 00 }
        $c = { 55 8B EC FF 75 08 }

    condition:
        any of ($a, $b, $c)
}
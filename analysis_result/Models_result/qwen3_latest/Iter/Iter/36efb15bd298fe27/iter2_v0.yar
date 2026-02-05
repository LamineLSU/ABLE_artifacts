rule ExitProcess_Indicators
{
    meta:
        description = "Identifies code that may call ExitProcess or similar functions"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        confidence = 75

    strings:
        $a = { FF 75 08 E8 C8 FF FF FF }
        $b = { FF 75 08 FF 15 AC B0 41 00 }
        $c = { 59 FF 75 08 FF 15 AC B0 41 00 }

    condition:
        any of ($a, $b, $c)
}
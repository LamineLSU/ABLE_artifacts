rule ExitDecisionPoints
{
    meta:
        description = "Detects exit decision points in malicious code"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        confidence = 70

    strings:
        $a = { FF 75 08 E8 ?? ?? ?? ?? }
        $b = { 55 8B EC FF 75 08 }
        $c = { FF 15 AC B0 41 00 }

    condition:
        all of ($a, $b, $c)
}
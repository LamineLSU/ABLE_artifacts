rule ExitProcess_Detection
{
    meta:
        author = "Security Researcher"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        description = "Detects calls to ExitProcess and related exit functions"

    strings:
        $a = { FF 75 08 E8 ?? ?? ?? ?? }
        $b = { FF 75 08 FF 15 ?? ?? ?? ?? }
        $c = { FF 75 08 E8 ?? ?? ?? ?? 59 }

    condition:
        any of them
}
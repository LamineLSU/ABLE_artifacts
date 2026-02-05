rule BypassExitProcess
{
    meta:
        description = "Bypasses ExitProcess by skipping critical instructions"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "YourName"

    strings:
        $a = { E8 ?? ?? ?? ?? 8B 06 83 C4 14 }
        $b = { 8B 06 83 C4 14 52 FF D0 }
        $c = { 83 C4 14 52 FF D0 }

    condition:
        all of them
}
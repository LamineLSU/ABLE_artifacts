rule EvasionCheck
{
    meta:
        description = "Detects potential sandbox evasion checks using CRT and system exit calls."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"

    strings:
        $a = { FF 75 08 FF 15 ?? ?? ?? ?? }  // Call to ExitProcess
        $b = { FF 75 08 E8 ?? ?? ?? ?? }      // Call to ___crtCorExitProcess
        $c = { 55 8B EC FF 75 08 }            // Function prologue

    condition:
        any of ($a, $b, $c)
}
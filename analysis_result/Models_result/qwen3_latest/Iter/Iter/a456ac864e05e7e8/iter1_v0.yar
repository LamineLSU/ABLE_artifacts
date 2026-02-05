rule ExitBypass
{
    meta:
        description = "Bypasses exit detection by targeting evasion logic"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { FF 75 08 E8 ?? ?? ?? ?? } // push ebp + call to ___crtCorExitProcess
        $b = { FF 15 AC B0 41 00 }        // direct call to ExitProcess
        $c = { 8B FF 55 8B EC FF 75 08 }  // prologue setup + push ebp
    condition:
        $a or $b or $c
}
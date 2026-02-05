rule Targeted_Exit_Calls
{
    meta:
        description = "Detects setup steps and exit call patterns in a specific code sequence."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        confidence = 85

    strings:
        $a = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? }  // Setup before exit call
        $b = { 59 FF 15 AC B0 41 00 }             // Call to ExitProcess
        $c = { 8B FF 55 8B EC FF 75 08 }             // Initial stack setup

    condition:
        all of ($a, $b, $c)
}
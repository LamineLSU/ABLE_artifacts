rule ExitDecision
{
    meta:
        description = "Detects exit decision logic based on stack setup and control flow"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        confidence = 60

    strings:
        $a = { 55 8B EC FF 75 08 E8 C8 FF FF FF }  // Setup before exit
        $b = { FF 75 08 FF 15 AC B0 41 00 }         // Push and call to ExitProcess
        $c = { E8 C8 FF FF FF 59 }               // Call to ___crtCorExitProcess followed by pop ecx

    condition:
        all of ($a, $b, $c)
}
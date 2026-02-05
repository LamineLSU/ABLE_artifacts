rule Bypass_Sample
{
    meta:
        description = "Detects evasion techniques via conditional checks and process injection patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Cyber Threat Intelligence Unit"
        date = "2023-10-15"
    strings:
        $pattern0 = { FF 75 08 50 FF 15 ?? ?? ?? ?? } // TerminateProcess call with prior push
        $pattern1 = { FF 75 08 FF 15 ?? ?? ?? ?? }     // ExitProcess call with prior push
        $pattern2 = { C1 E8 08 A8 01 75 10 }           // Shifting and conditional check
    condition:
        all of them
}
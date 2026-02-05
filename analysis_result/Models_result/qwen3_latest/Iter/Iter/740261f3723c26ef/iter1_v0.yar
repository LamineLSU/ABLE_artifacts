rule Malware_Evasion_ExitProcess
{
    meta:
        description = "Detects malware evasion via ExitProcess calls"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2023-10-05"

    strings:
        $a = { 8B FF 55 8B EC FF 75 08 }  // Initial stack setup
        $b = { 8B EC FF 75 08 E8 ?? ?? ?? ?? }  // Call to __crtCorExitProcess
        $c = { 59 FF 75 08 FF 15 ?? ?? ?? ?? }  // Call to ExitProcess

    condition:
        any of ($a, $b, $c)
}
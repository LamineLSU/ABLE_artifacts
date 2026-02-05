rule Malware_Escape
{
    meta:
        description = "Detects process termination evasion via ExitProcess or CRT exit functions"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"

    strings:
        $a = { FF 75 08 FF 15 ?? ?? ?? ?? }  // ExitProcess call
        $b = { FF 75 08 E8 ?? ?? ?? ?? 59 }  // CRT exit function
        $c = { FF 15 ?? ?? ?? ?? 59 }       // Direct ExitProcess call

    condition:
        any of ($a, $b, $c)
}
rule ProcessTermination
{
    meta:
        description = "Detects process termination or related operations"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Malware Analyst"
        date = "2025-04-05"

    strings:
        $a = { E8 ?? ?? ?? ?? 83 F8 01 74 20 }  // Conditional jump after comparison
        $b = { FF 15 ?? ?? ?? ?? }               // General API call
        $c = { FF 15 A8 30 2E 01 }               // Call to ExitProcess

    condition:
        all of ($a, $b, $c)
}
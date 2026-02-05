rule Suspicious_ExitProcess_Call
{
    meta:
        description = "Detects suspicious calls to ExitProcess, possibly indicating termination of processes or evasion techniques."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
        date = "2023-10-10"

    strings:
        $a = { 83 7D FC 00 75 08 FF 15 ?? ?? ?? ?? }
        $b = { 75 08 6A 00 FF 15 ?? ?? ?? ?? }
        $c = { 89 45 FC 83 7D FC 00 75 08 6A 00 }

    condition:
        any of ($a, $b, $c)
}
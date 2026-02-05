rule MalwareExitProcess
{
    meta:
        description = "Detects a malicious payload that terminates itself using ExitProcess"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"
        severity = "high"
    strings:
        $a = { FF 15 ?? ?? ?? ?? }  // Call to ExitProcess
        $b = { FF 75 08 E8 ?? ?? ?? ?? 59 FF 75 08 FF 15 ?? ?? ?? ?? }  // Context around ExitProcess call
    condition:
        $a or $b
}
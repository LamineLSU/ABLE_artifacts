rule ExitProcessCall
{
    meta:
        description = "Detects calls to ExitProcess (common in process termination evasion)"
        cape_options = "bp0=$a+0,action0=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"
    strings:
        $a = { 53 FF 15 ?? ?? ?? ?? }  // Push ebx followed by call to ExitProcess
    condition:
        $a
}
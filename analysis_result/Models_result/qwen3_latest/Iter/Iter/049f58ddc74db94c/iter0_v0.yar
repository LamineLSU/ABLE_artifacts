rule ExitProcessCall
{
    meta:
        description = "Detects a call to ExitProcess (commonly used in Windows malware to terminate the process)"
        cape_options = "bp0=$a+0,action0=skip,count=0"
        author = "Security Researcher"
        date = "2025-04-05"

    strings:
        $a = { 53 E8 ?? ?? ?? } // push ebx followed by call (displacement is unknown)

    condition:
        $a
}
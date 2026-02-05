rule Malware_Escape_Calls
{
    meta:
        description = "Detects a malware that calls ExitProcess or similar functions to evade analysis"
        cape_options = "bp0=$pattern2+0,action0=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        $pattern0 = FF 75 08 E8 [0-9a-f]{4}
        $pattern1 = FF 75 08 FF 15 [0-9a-f]{4}
        $pattern2 = { 8B FF 55 8B EC FF 75 08 }

    condition:
        all of them
}
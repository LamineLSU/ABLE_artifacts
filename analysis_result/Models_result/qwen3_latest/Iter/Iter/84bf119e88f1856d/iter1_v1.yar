rule BypassExitProcess
{
    meta:
        description = "Bypass ExitProcess call detection"
        author = "Security Researcher"
        date = "2023-10-05"
        cape_options = true

    strings:
        $a = { FF 75 08 FF 15 ?? ?? ?? ?? }
        $b = { 55 8B EC E8 ?? ?? ?? ?? }
        $c = { 59 FF 75 08 FF 15 ?? ?? ?? ?? }

    condition:
        any of $a, $b, $c
}
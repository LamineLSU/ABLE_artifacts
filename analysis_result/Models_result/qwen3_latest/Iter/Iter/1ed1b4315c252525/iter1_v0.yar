rule ExitDecision
{
    meta:
        description = "Detects exit decision and evasion checks in the original trace"
        confidence = 75

    strings:
        $a = /FF 75 08 FF 15 ?? ?? ?? ??/  // push + call to ExitProcess
        $b = /E8 C1 FFFF FF 59/             // call to ___crtCorExitProcess + pop ecx
        $c = /55 8B EC FF 75 08/            // function prologue

    condition:
        all of ($a, $b, $c)
}
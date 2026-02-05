rule EvasionDetection
{
    meta:
        description = "Detects evasion techniques involving ExitProcess calls and obfuscated code patterns"
        cape_options = "bp0=$call_exit1+0,action0=skip,bp1=$call_obf1+0,action1=skip,bp2=$or_al+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2023-10-15"

    strings:
        // Pattern 1: ExitProcess call with preceding add esp and pushes
        $call_exit1 = { 83 C4 14 52 52 52 FF D0 }

        // Pattern 2: Obfuscated call to 0041EB17 with lea and push instructions
        $call_obf1 = { 8D B0 A0 0C 00 00 56 50 E8 ?? ?? ?? ?? }

        // Pattern 3: OR AL, 8Bh and surrounding instructions
        $or_al = { 55 0C 8B 8B 06 6 83 C4 14 }

    condition:
        any of ($call_exit1, $call_obf1, $or_al)
}
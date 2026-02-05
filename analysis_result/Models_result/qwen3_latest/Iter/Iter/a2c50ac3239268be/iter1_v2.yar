rule ExitBypassPatterns
{
    meta:
        description = "Identifies potential bypass points in exit logic by capturing critical function calls and conditional jumps."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2023-10-15"

    strings:
        // Pattern 0: mov eax, [address], push eax, call ExitProcess
        $pattern0 = { A1 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? } (11)

        // Pattern 1: je [address], call FreeLibrary
        $pattern1 = { 74 ?? E8 ?? ?? ?? ?? } (7)

        // Pattern 2: call ExitProcess preceded by push eax
        $pattern2 = { E8 ?? ?? ?? ?? 50 } (6)

    condition:
        all of them
}
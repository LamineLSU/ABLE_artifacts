rule EvasionBypass
{
    meta:
        description = "Detects evasion techniques involving ExitProcess call setup"
        cape_options = "bp0=$setup1+0,action0=skip,bp1=$exit_sequence+0,action1=skip,bp2=$full_chain+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2023-10-15"

    strings:
        // Pattern 1: Function call setup followed by EAX loading
        $setup1 = { E8 ?? ?? ?? ?? 8B 55 0C 8B 06 } (10)

        // Pattern 2: Stack adjustment and final call to ExitProcess
        $exit_sequence = { 83 C4 14 52 FF D0 } (6)

        // Pattern 3: Full setup chain leading to ExitProcess
        $full_chain = { E8 ?? ?? ?? ?? 8B 55 0C 8B 06 83 C4 14 52 FF D0 } (16)

    condition:
        (all of ($setup1, $exit_sequence) or $full_chain)
}
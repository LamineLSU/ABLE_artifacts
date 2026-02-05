rule EvasionCheck
{
    meta:
        description = "Detects evasion checks and exit logic in the target sample"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "AI Assistant"
        date = "2023-10-15"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 66 83 F8 01 75 ?? } // Call + cmp AX + jne
        $pattern1 = { 66 83 F8 01 75 ?? } // cmp AX + jne (evasion check)
        $pattern2 = { FF 15 ?? ?? ?? ?? } // Call to ExitProcess (exit logic)

    condition:
        all of them
}
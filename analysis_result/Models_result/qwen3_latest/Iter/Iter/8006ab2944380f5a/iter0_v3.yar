rule IndirectExitCall
{
    meta:
        description = "Detects indirect call to ExitProcess used in evasion techniques"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Security Researcher"
        date = "2023-10-05"
        reference = "https://example.com"

    strings:
        $a = { 8B 52 ?? 8B 06 83 C4 ?? 52 FF D0 } // Full block leading to call
        $b = { 8B 06 83 C4 ?? 52 FF D0 } // Core block with address offset
        $c = { 83 C4 ?? 52 FF D0 } // Final part with address offset

    condition:
        any of ($a, $b, $c)
}
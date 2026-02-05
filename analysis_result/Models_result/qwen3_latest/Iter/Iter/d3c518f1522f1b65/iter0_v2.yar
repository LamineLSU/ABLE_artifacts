rule TerminationFlow
{
    meta:
        description = "Detects code that leads to a process termination (e.g., ExitProcess)"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Security Researcher"
        date = "2025-03-15"
        tags = ["malware", "termination", "exitprocess", "control-flow"]

    strings:
        // First test and jump (test eax, eax; je 0x0A)
        $a = { 85 C0 74 0A } // test eax, eax; je 0x0A

        // Second test and jump (test eax, eax; je 0x12)
        $b = { 85 C0 74 12 } // test eax, eax; je 0x12

        // Third test and jump (test eax, eax; je 0x05)
        $c = { 85 C0 74 05 } // test eax, eax; je 0x05

        // Call to ExitProcess (assuming it's at offset 0x20 from the start of the block)
        $d = { E8 00 00 00 00 } // call 0x20

    condition:
        ( $a or $b or $c ) and $d
}
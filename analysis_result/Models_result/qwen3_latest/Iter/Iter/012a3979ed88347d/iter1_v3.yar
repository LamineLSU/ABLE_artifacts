rule EvasionHook
{
    meta:
        description = "Detects evasion logic preceding termination"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "SecurityResearcher"
        date = "2023-11-01"

    strings:
        $a = { 85 C0 74 12 8B 4D F8 } // Test/je + next instruction
        $b = { 85 C0 0F 84 ?? ?? ?? ?? } // Test/je with variable offset
        $c = { E8 ?? ?? ?? ?? 8B 4D F8 } // Call + next instruction

    condition:
        all of ($a, $b, $c)
}
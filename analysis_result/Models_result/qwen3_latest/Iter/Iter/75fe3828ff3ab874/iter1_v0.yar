rule ControlFlowPatterns
{
    meta:
        description = "Identifies control flow patterns and function calls"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        confidence = 95
        author = "Your Name"
        date = "2025-04-15"

    strings:
        $a = { 8B 4D F8 85 C0 74 ?? } // Test and conditional jump
        $b = { 85 C0 0F 84 ?? ?? ?? ?? } // Test and conditional jump with long offset
        $c = { 8B 45 FC E8 ?? ?? ?? ?? } // Move and call

    condition:
        all of them
}
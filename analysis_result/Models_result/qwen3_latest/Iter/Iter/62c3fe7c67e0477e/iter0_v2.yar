rule ConditionalJumpToTermination
{
    meta:
        description = "Detects a conditional jump to termination logic"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"
    strings:
        $a = { 0F 84 } // je instruction (conditional jump)
        $b = { 01 11 61 90 } // relative offset to 0x01116190
    condition:
        $a at 0x0111617C and $b at 0x0111617C
}
rule ConditionalJumpAndCall
{
    meta:
        description = "Detects a conditional jump followed by a call to an external function."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,count=0"
    strings:
        $a = { 74 0E } // JE instruction (JMP if equal)
        $b = { E8 ?? ?? ?? ?? } // CALL instruction with 4-byte displacement
    condition:
        $a and $b
}
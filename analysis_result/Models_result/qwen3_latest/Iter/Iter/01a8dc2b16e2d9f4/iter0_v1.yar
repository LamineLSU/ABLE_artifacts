rule ConditionalJumpWithRegisterLoad
{
    meta:
        description = "Detects a conditional jump (JE) following a TEST instruction and a register load."
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 85 C0 74 ?? 8B 4D 08 }
    condition:
        $a
}
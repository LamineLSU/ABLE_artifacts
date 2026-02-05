rule ConditionalJump
{
    meta:
        description = "Detects a conditional jump (je) after a test eax, eax instruction"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 85 C0 74 ?? ?? ?? }
    condition:
        $a
}
rule ConditionalJumpWithCall
{
    meta:
        description = "Conditional jump (JNE) followed by a function call"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 85 C0 75 07 50 FF 15 ?? ?? ?? ?? }
    condition:
        $a
}
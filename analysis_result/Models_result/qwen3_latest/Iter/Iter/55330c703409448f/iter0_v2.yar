rule ConditionalJump
{
    meta:
        description = "Conditional jump that may alter execution flow"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 74 ?? }  // JE instruction with offset
    condition:
        $a
}
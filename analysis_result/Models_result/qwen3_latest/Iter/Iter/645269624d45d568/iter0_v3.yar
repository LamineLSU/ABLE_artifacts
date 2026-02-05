rule ConditionalCheck
{
    meta:
        description = "Conditional check for a specific value"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { E8 ?? ?? ?? ?? } {83 F8 01}
    condition:
        $a
}
rule ConditionalJumpAfterCall
{
    meta:
        description = "Conditional jump after a function call, possibly indicating an evasion check."
        cape_options = "bp0=$0+0,action0=skip,count=0"
    strings:
        $0 = { E8 CD 3D 00 00 83 F8 01 74 20 }
    condition:
        $0
}
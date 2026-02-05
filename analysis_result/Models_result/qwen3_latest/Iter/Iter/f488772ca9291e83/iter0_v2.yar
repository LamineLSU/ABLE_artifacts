rule ConditionalJumpToExit
{
    meta:
        description = "Detects a conditional jump that may lead to ExitProcess"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 85 C0 74 ?? }
    condition:
        all of them
}
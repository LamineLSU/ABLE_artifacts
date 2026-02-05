rule SkipExitProcessJump
{
    meta:
        description = "Skips the jump to ExitProcess"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { EB E1 ?? ?? ?? ?? FF 96 ?? ?? ?? ?? }
    condition:
        $a
}
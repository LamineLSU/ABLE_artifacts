rule FirstExitCall
{
    meta:
        description = "Detects the first exit call after stack frame setup"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { FF 75 08 E8 C8 ?? ?? ?? }
    condition:
        $a
}
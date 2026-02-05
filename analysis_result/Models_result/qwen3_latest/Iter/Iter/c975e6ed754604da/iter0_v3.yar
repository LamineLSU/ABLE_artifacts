rule bypass_1
{
    meta:
        description = "Bypasses the call to ___crtCorExitProcess"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { FF 75 08 E8 ?? ?? ?? ?? 59 }
    condition:
        $a
}
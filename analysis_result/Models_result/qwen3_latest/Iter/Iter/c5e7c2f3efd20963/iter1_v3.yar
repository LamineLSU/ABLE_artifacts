rule SpecificCallToCRTExitProcess
{
    meta:
        description = "Identifies the specific call to ___crtCorExitProcess at 00427B11"
        cape_options = "bp0=$a+0,action0=skip,count=0"
        author = "Your Name"
        date = "2025-04-15"

    strings:
        $a = { FF 75 08 E8 ?? ?? ?? ?? }  // FF7508 (push dword [ebp+08h]) followed by a CALL

    condition:
        $a
}
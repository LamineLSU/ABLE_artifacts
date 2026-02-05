rule bypass_call_to_crtCorExitProcess
{
    meta:
        description = "Bypasses the call to ___crtCorExitProcess by skipping the push and call sequence"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { FF 75 08 E8 ?? ?? ?? ?? }
    condition:
        $a
}
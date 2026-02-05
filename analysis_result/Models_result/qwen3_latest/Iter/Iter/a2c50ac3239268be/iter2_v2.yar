rule bypass_exitprocess
{
    meta:
        description = "Bypasses ExitProcess by skipping the call"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 50 E8 ?? ?? ?? ?? }
    condition:
        $a
}
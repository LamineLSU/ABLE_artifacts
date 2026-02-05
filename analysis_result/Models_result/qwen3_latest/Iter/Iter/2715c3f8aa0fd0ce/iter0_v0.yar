rule TerminateProcessCall
{
    meta:
        description = "Call to TerminateProcess with preceding push eax"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 50 FF 15 ?? ?? ?? ?? }
    condition:
        $a
}
rule ExitProcessCallPattern1
{
    meta:
        description = "Pattern for the call to ExitProcess with preceding push instruction"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { FF 75 08 FF 15 ?? ?? ?? ?? }
    condition:
        $a
}
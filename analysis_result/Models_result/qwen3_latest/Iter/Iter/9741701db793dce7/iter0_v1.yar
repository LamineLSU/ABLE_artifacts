rule ExitCallWithPushZero
{
    meta:
        description = "Detects a call to ExitProcess preceded by a push 0"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 6A 00 FF 15 ?? ?? ?? ?? }
    condition:
        $a
}
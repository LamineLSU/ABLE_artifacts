rule ExitProcess_Call1
{
    meta:
        description = "Detects a call to ExitProcess via a direct jump"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { FF 75 08 E8 ?? ?? ?? ?? 59 }
    condition:
        $a
}
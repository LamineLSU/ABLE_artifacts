rule ExitProcessChain
{
    meta:
        description = "Detects a sequence leading to ExitProcess"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { FF 15 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? }
    condition:
        $a
}
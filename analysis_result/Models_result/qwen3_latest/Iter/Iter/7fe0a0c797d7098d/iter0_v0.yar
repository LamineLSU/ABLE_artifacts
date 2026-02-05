rule ExitProcessCall
{
    meta:
        description = "Potential ExitProcess call sequence"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 50 FF 15 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? }
    condition:
        $a
}
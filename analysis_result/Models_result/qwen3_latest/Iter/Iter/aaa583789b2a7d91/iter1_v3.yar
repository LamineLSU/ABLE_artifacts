rule ExitProcessCall
{
    meta:
        description = "Call to ExitProcess function"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { E8 2D 01 00 00 }
    condition:
        $a
}
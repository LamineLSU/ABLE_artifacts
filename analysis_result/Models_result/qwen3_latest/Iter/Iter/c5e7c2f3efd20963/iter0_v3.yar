rule Pattern0
{
    meta:
        description = "Pattern targeting the first call to ExitProcess (LIBCMT.LIB)"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { FF 75 08 E8 ?? ?? ?? ?? }
    condition:
        $a
}
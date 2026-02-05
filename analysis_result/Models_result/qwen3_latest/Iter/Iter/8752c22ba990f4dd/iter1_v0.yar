rule ExitCheckPattern1
{
    meta:
        description = "Pattern for the first call to exit function"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { FF 75 08 E8 C1 FF FF FF }
    condition:
        $a
}
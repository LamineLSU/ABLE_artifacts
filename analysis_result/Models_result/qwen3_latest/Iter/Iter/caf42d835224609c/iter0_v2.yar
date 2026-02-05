rule Pattern1
{
    meta:
        description = "Call to ExitProcess and preceding push 0"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 6A 00 E8 ?? ?? ?? ?? }
    condition:
        $a
}